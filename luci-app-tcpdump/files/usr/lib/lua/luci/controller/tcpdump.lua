-- tcpdump.lua - Advanced and Robust LuCI controller for tcpdump
-- Final Version: Implements robust process identification via command-line signature,
-- removing the unreliable PID file dependency and ensuring safe process termination.

module("luci.controller.admin.services.tcpdump", package.seeall)

local sys = require "luci.sys"
local http = require "luci.http"
local util = require "luci.util"
local fs = require "nixio.fs"

-- Configuration constants
local PCAP_FILE = "/tmp/tcpdump.pcap"
-- This is our unique process signature. We use it to find the correct process.
local PROCESS_SIGNATURE = "tcpdump -w " .. PCAP_FILE

function index()
    entry({"admin", "services", "tcpdump"}, view("admin_services/tcpdump"), _("TCPDump"), 70).dependent = true
    
    -- API endpoints for the modern frontend
    entry({"admin", "services", "tcpdump", "interfaces"}, call("action_interfaces"))
    entry({"admin", "services", "tcpdump", "status"}, call("action_status"))
    entry({"admin", "services", "tcpdump", "start"}, call("action_start"))
    entry({"admin", "services", "tcpdump", "stop"}, call("action_stop"))
    entry({"admin", "services", "tcpdump", "download"}, call("action_download"))
    entry({"admin", "services", "tcpdump", "delete"}, call("action_delete"))
    entry({"admin", "services", "tcpdump", "broute"}, call("action_broute"))
end

-- [RELIABILITY UPGRADE]
-- Get PID by scanning the process list for our unique signature in real-time.
-- This is the robust replacement for the stale PID file method.
local function get_pid_by_signature()
    -- Command breakdown:
    -- 1. `ps`: List all processes. In some busybox versions, 'ps w' provides wider output.
    -- 2. `grep "%s"`: Find the line containing our unique signature.
    -- 3. `grep -v 'grep'`: Exclude the grep process itself from the results.
    -- 4. `awk '{print $1}'`: Print the first column, which is the PID.
    local cmd = string.format("ps w | grep '%s' | grep -v 'grep' | awk '{print $1}'", PROCESS_SIGNATURE)
    local pid = util.trim(sys.exec(cmd))
    
    -- Return the PID only if it's a valid number, otherwise return nil.
    if pid and tonumber(pid) then
        return pid
    end
    return nil
end

-- JSON response helper
local function json_response(data)
    http.prepare_content("application/json")
    http.write_json(data)
end

-- API: Return list of network interfaces
function action_interfaces()
    local interfaces = {}
    -- Using sys.net.get_interfaces() is more robust than parsing ifconfig
    for _, dev in ipairs(sys.net.get_interfaces()) do
        table.insert(interfaces, dev:name())
    end
    json_response(interfaces)
end

-- API: Return current status of tcpdump
function action_status()
    -- Now uses the new, reliable PID detection function.
    local pid = get_pid_by_signature()
    local file_stat = fs.stat(PCAP_FILE)
    local ebtables_installed = sys.pkg.is_installed("ebtables")
    local broute_enabled = false

    if ebtables_installed then
        -- Check if the broute rule exists and is active. The '-q' makes grep silent.
        local broute_check_cmd = "ebtables -t broute -L FORWARD | grep -- '-p 802_1Q --vlan-encap 0x8100 -j broute --broute-target ACCEPT' -q"
        broute_enabled = (sys.call(broute_check_cmd) == 0)
    end
    
    json_response({
        running = (pid ~= nil),
        pid = pid,
        file_exists = (file_stat ~= nil),
        file_size = file_stat and file_stat.size or 0,
        ebtables_installed = ebtables_installed,
        broute_enabled = broute_enabled,
    })
end

-- API: Start the tcpdump capture
function action_start()
    -- Check for running process using the new function before starting.
    if get_pid_by_signature() then
        return json_response({ success = false, message = "抓包已在运行中。" })
    end

    -- Security validation for all inputs
    local iface = http.formvalue("interface")
    local filter = http.formvalue("filter") or ""
    local filesize_mb = tonumber(http.formvalue("filesize"))
    local count = tonumber(http.formvalue("count"))

    -- 1. Validate interface exists
    local iface_valid = false
    if iface then
        for _, dev in ipairs(sys.net.get_interfaces()) do
            if dev:name() == iface then
                iface_valid = true
                break
            end
        end
    end
    if not iface_valid then
        return json_response({ success = false, message = "错误：无效的网络接口。" })
    end
    
    -- 2. Basic validation for other parameters to prevent command injection
    if filesize_mb and not (filesize_mb > 0) then filesize_mb = nil end
    if count and not (count > 0) then count = nil end
    -- A simple filter validation to prevent shell metacharacters like ; & | ` $ ()
    if filter:match("[;&|`$()]") then
        return json_response({ success = false, message = "错误：过滤器包含无效字符。" })
    end

    -- Build the command safely
    local cmd_parts = {"tcpdump", "-i", iface, "-w", PCAP_FILE}
    if filesize_mb then
        table.insert(cmd_parts, "-C")
        table.insert(cmd_parts, tostring(math.floor(filesize_mb)))
        table.insert(cmd_parts, "-W")
        table.insert(cmd_parts, "1") -- Rotate between 1 file
    end
    if count then
        table.insert(cmd_parts, "-c")
        table.insert(cmd_parts, tostring(math.floor(count)))
    end

    -- The command is executed without creating a PID file.
    -- The '&' at the end runs it in the background.
    local full_cmd_str
    if filter and #filter > 0 then
        -- Safely quote the filter argument
        full_cmd_str = table.concat(cmd_parts, " ") .. " " .. "'" .. filter:gsub("'", "'\\''") .. "'"
    else
        full_cmd_str = table.concat(cmd_parts, " ")
    end
    sys.call(full_cmd_str .. " >/dev/null 2>&1 &")
    
    -- Wait a moment to allow the process to start, then verify it's running.
    util.nanosleep(500 * 1000 * 1000) -- 500ms
    if get_pid_by_signature() then
        json_response({ success = true, message = "抓包已成功启动。" })
    else
        json_response({ success = false, message = "启动抓包失败，请检查参数或系统日志。" })
    end
end

-- API: Stop the tcpdump capture
function action_stop()
    -- Find the real PID in real-time before killing.
    local pid = get_pid_by_signature()
    if pid then
        -- Send SIGTERM (15) for a graceful shutdown, allowing tcpdump to flush buffers.
        sys.call("kill " .. pid)
    end
    
    -- As a safety measure, always try to disable broute on stop
    sys.call("ebtables -t broute -D FORWARD -p 802_1Q --vlan-encap 0x8100 -j broute --broute-target ACCEPT >/dev/null 2>&1")
    
    -- Wait a moment and verify the process is truly gone.
    util.nanosleep(500 * 1000 * 1000)
    if not get_pid_by_signature() then
        json_response({ success = true, message = "抓包已成功停止。" })
    else
        json_response({ success = false, message = "停止进程失败，可能需要手动干预。" })
    end
end

-- API: Download the capture file
function action_download()
    if fs.access(PCAP_FILE) then
        http.prepare_content("application/vnd.tcpdump.pcap")
        http.set_header("Content-Disposition", "attachment; filename=\"tcpdump.pcap\"")
        http.write_file(PCAP_FILE)
    else
        http.status(404, "Not Found")
        http.write("文件未找到。")
    end
end

-- API: Delete the capture file
function action_delete()
    if fs.access(PCAP_FILE) then
        fs.unlink(PCAP_FILE)
        json_response({ success = true, message = "文件已成功删除。" })
    else
        json_response({ success = false, message = "文件不存在或已被删除。" })
    end
end

-- API: Manage ebtables brouting for layer 2 traffic
function action_broute()
    if not sys.pkg.is_installed("ebtables") then
        return json_response({ success = false, message = "错误：ebtables 未安装。" })
    end

    local enable = http.formvalue("enable") == "true"
    local rule = "-p 802_1Q --vlan-encap 0x8100 -j broute --broute-target ACCEPT"
    
    if enable then
        -- Check if the rule already exists to avoid duplicates
        local check_cmd = "ebtables -t broute -L FORWARD | grep -- '-p 802_1Q --vlan-encap 0x8100 -j broute --broute-target ACCEPT' -q"
        if sys.call(check_cmd) ~= 0 then
            sys.call("ebtables -t broute -A FORWARD " .. rule)
            json_response({ success = true, message = "二层桥接流量捕获已开启。" })
        else
            json_response({ success = true, message = "功能已处于开启状态。" })
        end
    else
        -- Deleting the rule is idempotent; no harm if it doesn't exist.
        sys.call("ebtables -t broute -D FORWARD " .. rule .. " >/dev/null 2>&1")
        json_response({ success = true, message = "二层桥接流量捕获已关闭。" })
    end
end
