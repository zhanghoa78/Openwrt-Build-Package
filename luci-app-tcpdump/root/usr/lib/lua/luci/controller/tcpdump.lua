local M = {}

-- 确保与旧系统兼容
if module then
    module("luci.controller.tcpdump", package.seeall)
end

-- 导入必要的库
local http = require "luci.http"
local util = require "luci.util"
local nixio = require "nixio"

-- 常量定义
local CAPTURE_FILE = "/tmp/tcpdump.pcap"
local MAX_CAPTURE_SIZE = 50 * 1024 * 1024
local MAX_CAPTURE_DURATION = 3600

-- 辅助函数：JSON响应
local function json_response(data)
    http.prepare_content("application/json")
    http.write_json(data)
end

-- 辅助函数：安全执行
local function safe_execute(action_func, error_msg)
    local ok, err = pcall(action_func)
    if not ok and err then
        util.exec("logger -t tcpdump_luci '" .. error_msg .. ": " .. tostring(err) .. "'")
        return false, err
    end
    return true
end

-- 路由注册
function M.index()
    entry({"admin", "services", "tcpdump"}, firstchild(), _("TCPDump"), 60).dependent = false
    entry({"admin", "services", "tcpdump", "overview"}, template("tcpdump/overview"), _("Overview"), 1)
    entry({"admin", "services", "tcpdump", "interfaces"}, call("action_interfaces"))
    entry({"admin", "services", "tcpdump", "ajax_status"}, call("action_ajax_status"))
    entry({"admin", "services", "tcpdump", "start"}, call("action_start"))
    entry({"admin", "services", "tcpdump", "stop"}, call("action_stop"))
    entry({"admin", "services", "tcpdump", "download"}, call("action_download"))
    entry({"admin", "services", "tcpdump", "delete"}, call("action_delete"))
end

-- 获取网络接口
function M.action_interfaces()
    local interfaces = {}
    local list = util.exec("ls /sys/class/net/ 2>/dev/null")

    if list and list ~= "" then
        for iface in list:gmatch("[^%s]+") do
            iface = iface:match("^%s*(.-)%s*$")
            if iface ~= "" and iface ~= "lo" then
                table.insert(interfaces, iface)
            end
        end
    end

    if #interfaces == 0 then
        interfaces = {"br-lan", "eth0", "eth1", "wlan0", "wlan1"}
    end

    table.sort(interfaces)
    json_response(interfaces)
end

-- 检查命令是否存在
local function command_exists(cmd)
    return util.exec("command -v " .. cmd .. " >/dev/null 2>&1 && echo 1 || echo 0"):match("^1")
end

-- 格式化文件大小
local function format_file_size(bytes)
    if not bytes or bytes == 0 then
        return "0 B"
    end
    local sizes = {"B", "KB", "MB", "GB"}
    local i = 1
    local size = bytes
    while size > 1024 and i < #sizes do
        size = size / 1024
        i = i + 1
    end
    return string.format("%.2f %s", size, sizes[i])
end

-- 获取tcpdump进程PID
local function get_tcpdump_pids_for_our_capture()
    -- 方法1: 使用ps命令获取PID
    local ps_output = util.exec("ps w | grep '[t]cpdump ' | grep -- '-w " .. CAPTURE_FILE .. "' | grep -v 'grep' | awk '{print $1}'")
    if ps_output and ps_output ~= "" then
        local pids = {}
        for pid in ps_output:gmatch("%d+") do
            table.insert(pids, tonumber(pid))
        end
        if #pids > 0 then
            return pids
        end
    end
    
    -- 方法2: 备用方式
    local ps_cmd = "ps w | grep tcpdump | grep -v grep | grep '" .. CAPTURE_FILE .. "'"
    local ps_output = util.exec(ps_cmd)
    if ps_output and ps_output ~= "" then
        local pid = ps_output:match("^%s*(%d+)")
        if pid then
            return {tonumber(pid)}
        end
    end
    
    -- 方法3: 从/proc目录查找
    if command_exists("ls") then
        local proc_output = util.exec("ls -d /proc/[0-9]* 2>/dev/null")
        if proc_output and proc_output ~= "" then
            local pids = {}
            for pid_dir in proc_output:gmatch("/proc/(%d+)") do
                local pid = tonumber(pid_dir)
                if pid then
                    local cmdline = util.exec("cat /proc/" .. pid .. "/cmdline 2>/dev/null | tr '\\0' ' '")
                    if cmdline and cmdline:match("tcpdump") and cmdline:match(CAPTURE_FILE:gsub("/", "%/%")) then
                        table.insert(pids, pid)
                    end
                end
            end
            if #pids > 0 then
                return pids
            end
        end
    end
    
    return {}
end

-- 内部停止函数
local function action_stop_internal()
    if command_exists("killall") then
        util.exec("killall tcpdump 2>/dev/null")
    end
    
    util.exec("sleep 1")
    
    local max_retries = 3
    
    for attempt = 1, max_retries do
        local pids_to_kill = get_tcpdump_pids_for_our_capture()
        
        if #pids_to_kill == 0 then
            break
        end
        
        local pids_str = table.concat(pids_to_kill, " ")
        local kill_signal = attempt == 1 and "" or "-9"
        util.exec("kill " .. kill_signal .. " " .. pids_str .. " 2>/dev/null")
        util.exec("sleep 2")
    end
    
    local remaining_pids = get_tcpdump_pids_for_our_capture()
    if #remaining_pids > 0 then
        local remaining_pids_str = table.concat(remaining_pids, ", ")
        util.exec("echo 'Failed to stop tcpdump processes: " .. remaining_pids_str .. "' >> /tmp/tcpdump_stop_errors.log 2>&1")
    end
end

-- 清理抓包文件
local function cleanup_capture_files()
    util.exec("rm -f " .. CAPTURE_FILE .. "* 2>/dev/null")
end

-- 检查状态
function M.action_ajax_status()
    local result = {
        running = false,
        file_exists = false,
        file_size = 0,
        file_size_human = "0 B",
        pid = nil,
        interface = nil
    }

    safe_execute(function()
        local ps_output = util.exec("ps w | grep '[t]cpdump ' | grep -- '-w " .. CAPTURE_FILE .. "' | head -1")
        if ps_output and ps_output ~= "" then
            local pid = ps_output:match("^%s*(%d+)")
            if pid then
                result.running = true
                result.pid = pid
                local interface = ps_output:match("-i%s+(%S+)")
                if interface then
                    result.interface = interface
                end
            end
        end

        local stat = nixio.fs.stat(CAPTURE_FILE)
        if stat then
            result.file_exists = true
            result.file_size = stat.size
            result.file_size_human = format_file_size(stat.size)
        end
    end, "Status check error")

    json_response(result)
end

-- 过滤器验证
local function validate_filter(filter)
    if not filter or filter == "" then
        return true
    end
    
    if filter:match("[;&|$`\\t\\n\\r]") then
        return false
    end
    
    if not filter:match("^[A-Za-z0-9%s%(%%)=%<%>:_.,%-/%*]+") then
        return false
    end
    
    local open_brackets = select(2, filter:gsub("%(", ""))
    local close_brackets = select(2, filter:gsub("%)", ""))
    if open_brackets ~= close_brackets then
        return false
    end
    
    return true
end

-- 启动抓包
function M.action_start()
    local interface = http.formvalue("interface")
    local filter = http.formvalue("filter") or ""
    local count = http.formvalue("count") or ""
    local duration = http.formvalue("duration") or ""

    local validation_checks = {
        { condition = not interface or interface == "", message = "请选择网络接口" },
        { condition = not interface:match("^[A-Za-z0-9%-_%%.]+"), message = "无效的接口名称" },
        { condition = interface ~= "" and not nixio.fs.stat("/sys/class/net/" .. interface), message = "网络接口不存在" },
        { condition = not validate_filter(filter), message = "无效的过滤器格式，请避免使用特殊字符" },
        { condition = not command_exists("tcpdump"), message = "tcpdump 未安装" }
    }

    for _, check in ipairs(validation_checks) do
        if check.condition then
            json_response({success = false, message = check.message})
            return
        end
    end

    safe_execute(action_stop_internal, "Failed to stop existing processes")
    safe_execute(cleanup_capture_files, "Failed to clean capture files")

    local cmd_parts = {
        "tcpdump",
        "-i", interface,
        "-w", CAPTURE_FILE,
        "-U",
        "-C", tostring(MAX_CAPTURE_SIZE / 1024 / 1024)
    }
    local message_parts = {}

    local count_num = tonumber(count)
    if count_num and count_num > 0 then
        table.insert(cmd_parts, "-c")
        table.insert(cmd_parts, tostring(count_num))
        table.insert(message_parts, "捕获 " .. count .. " 个包后停止")
    end

    local duration_num = tonumber(duration)
    if duration_num and duration_num > 0 and duration_num <= MAX_CAPTURE_DURATION then
        table.insert(message_parts, "捕获 " .. duration .. " 秒后停止")
        cmd_parts = {"timeout", tostring(duration_num)} .. cmd_parts
    end

    if filter ~= "" then
        table.insert(cmd_parts, filter)
    end

    local cmd = table.concat(cmd_parts, " ") .. " 2>/var/log/tcpdump_luci.log &"
    os.execute(cmd)
    util.exec("sleep 1")

    local pids_after_start = get_tcpdump_pids_for_our_capture()
    local success = (#pids_after_start > 0)

    if success then
        local message = "TCPDump 启动成功"
        if #message_parts > 0 then
            message = message .. " (" .. table.concat(message_parts, "；") .. ")"
        else
            message = message .. " (请手动停止，文件大小限制: " .. format_file_size(MAX_CAPTURE_SIZE) .. ")"
        end
        json_response({success = true, message = message, pid = pids_after_start[1]})
    else
        json_response({success = false, message = "TCPDump 启动失败，请检查接口或过滤器"})
    end
end

-- 停止抓包
function M.action_stop()
    local result = {success = true, message = ""}

    safe_execute(action_stop_internal, "Failed to stop tcpdump processes")

    local pids_still_running = get_tcpdump_pids_for_our_capture()
    if #pids_still_running > 0 then
        result.success = false
        result.message = "无法完全停止 tcpdump 进程，可能需要手动干预（PID: " .. table.concat(pids_still_running, ", ") .. "）"
    else
        result.message = "抓包已停止，文件已保存可供下载"
    end

    json_response(result)
end

-- 下载文件
function M.action_download()
    local stat = nixio.fs.stat(CAPTURE_FILE)

    if not stat then
        http.status(404, "Not Found")
        http.prepare_content("text/plain")
        http.write("Capture file does not exist")
        return
    end

    if stat.size == 0 then
        http.status(400, "Bad Request")
        http.prepare_content("text/plain")
        http.write("Capture file is empty")
        return
    end

    if stat.size > MAX_CAPTURE_SIZE then
        http.status(413, "Payload Too Large")
        http.prepare_content("text/plain")
        http.write("File too large, please capture a smaller packet set")
        return
    end

    local file = io.open(CAPTURE_FILE, "rb")
    if file then
        local content = file:read("*a")
        file:close()

        http.header('Content-Type', 'application/vnd.tcpdump.pcap')
        http.header('Content-Disposition', 'attachment; filename="tcpdump_' .. os.date("%Y%m%d_%H%M%S") .. '.pcap"')
        http.header('Content-Length', tostring(#content))
        http.write(content)
    else
        http.status(500, "Internal Server Error")
        http.write("Failed to read capture file")
    end
end

-- 删除文件
function M.action_delete()
    local result = {success = false, message = "操作失败"}

    safe_execute(action_stop_internal, "Failed to stop processes")
    safe_execute(cleanup_capture_files, "Failed to clean files")

    local stat = nixio.fs.stat(CAPTURE_FILE)
    if not stat then
        result.success = true
        result.message = "抓包文件已删除"
    else
        result.message = "无法删除文件"
    end

    json_response(result)
end

return M
