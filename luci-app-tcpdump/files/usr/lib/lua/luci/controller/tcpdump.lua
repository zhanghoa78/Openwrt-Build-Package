module("luci.controller.tcpdump", package.seeall)

-- 定义常量，便于维护
local PID_FILE = "/var/run/tcpdump.pid"
local CAPTURE_FILE = "/tmp/tcpdump.pcap"
local EBTABLES_INSTALLED = (nixio.fs.access("/usr/sbin/ebtables"))

function index()
    entry({"admin", "services", "tcpdump"}, firstchild(), _("TCPDump"), 60).dependent = false
    entry({"admin", "services", "tcpdump", "overview"}, template("tcpdump/overview"), _("Overview"), 1)
    
    -- API 接口
    entry({"admin", "services", "tcpdump", "interfaces"}, call("action_interfaces"))
    entry({"admin", "services", "tcpdump", "status"}, call("action_status")) -- 合并后的状态接口
    entry({"admin", "services", "tcpdump", "start"}, call("action_start"))
    entry({"admin", "services", "tcpdump", "stop"}, call("action_stop"))
    entry({"admin", "services", "tcpdump", "download"}, call("action_download"))
    entry({"admin", "services", "tcpdump", "delete"}, call("action_delete"))
    entry({"admin", "services", "tcpdump", "broute"}, call("action_broute")) -- 新增：控制 ebtables
end

-- 辅助函数：检查 PID 是否正在运行
local function is_pid_running(pid)
    return pid and nixio.fs.access("/proc/" .. pid)
end

-- 辅助函数：读取文件内容
local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    return content and content:match("^%s*(.-)%s*$")
end

-- 获取网络接口列表 (逻辑不变)
function action_interfaces()
    local util = require "luci.util"
    local nixio = require "nixio"
    local http = require "luci.http"
    
    local interfaces = {}
    local virtual_interfaces = {"lo"}
    
    local status, err = pcall(function()
        local fd = nixio.fs.dir("/sys/class/net/")
        if fd then
            for entry in fd do
                if entry ~= "." and entry ~= ".." then
                    if not util.contains(virtual_interfaces, entry) then
                        table.insert(interfaces, entry)
                    end
                end
            end
            fd:close()
        end
    end)
    
    if not status or #interfaces == 0 then
        -- 尝试从 ip link 获取，作为更可靠的备用方案
        local ip_output = util.trim(util.exec("ip -o link show | cut -d' ' -f2 | cut -d: -f1"))
        if ip_output and ip_output ~= "" then
            for iface in ip_output:gmatch("[^%s]+") do
                if not util.contains(virtual_interfaces, iface) then
                    table.insert(interfaces, iface)
                end
            end
        else
            interfaces = {"br-lan", "eth0", "wlan0"} -- 最后的硬编码备用
        end
    end
    
    table.sort(interfaces)
    http.prepare_content("application/json")
    http.write_json(interfaces)
end

-- 统一的状态检查接口
function action_status()
    local util = require "luci.util"
    local nixio = require "nixio"
    local http = require "luci.http"
    
    local result = {
        running = false,
        file_exists = false,
        file_size = 0,
        pid = nil,
        interface = nil,
        size_limit = nil,
        ebtables_installed = EBTABLES_INSTALLED,
        broute_enabled = false
    }
    
    -- 检查 ebtables 状态
    if EBTABLES_INSTALLED then
        local broute_rules = util.trim(util.exec("ebtables -t broute -L BROUTING"))
        if broute_rules:find("ACCEPT") then
            result.broute_enabled = true
        end
    end
    
    local pid = read_file(PID_FILE)
    if is_pid_running(pid) then
        result.running = true
        result.pid = pid
        
        -- 从 /proc 获取更可靠的命令行信息
        local cmdline = read_file("/proc/" .. pid .. "/cmdline")
        if cmdline then
            cmdline = cmdline:gsub("\0", " ")
            result.interface = cmdline:match("-i%s+([%w%-_%.]+)")
            local size_mb = cmdline:match("TCPDUMP_SIZE_LIMIT=(%d+)")
            if size_mb then
                result.size_limit = tonumber(size_mb)
            end
        end
    end
    
    local stat = nixio.fs.stat(CAPTURE_FILE)
    if stat then
        result.file_exists = true
        result.file_size = stat.size
        
        -- 如果达到大小限制，自动停止
        if result.running and result.size_limit and stat.size >= result.size_limit * 1024 * 1024 then
            action_stop_internal()
            result.running = false -- 更新状态为已停止
            result.size_limit_reached = true
        end
    end
    
    http.prepare_content("application/json")
    http.write_json(result)
end

-- 内部停止函数，更可靠
local function action_stop_internal()
    local pid = read_file(PID_FILE)
    if is_pid_running(pid) then
        -- 优雅地终止
        os.execute("kill " .. pid .. " >/dev/null 2>&1")
        nixio.nanosleep(500000000) -- 等待 0.5 秒
    end

    -- 强制清理，作为保险
    if is_pid_running(pid) then
        os.execute("kill -9 " .. pid .. " >/dev/null 2>&1")
    end
    
    -- 最后的保障，清理所有可能的残留进程
    os.execute("pkill -f 'tcpdump.*" .. CAPTURE_FILE .. "' >/dev/null 2>&1")
    
    nixio.fs.unlink(PID_FILE)
end

-- 启动抓包
function action_start()
    local http = require "luci.http"
    local util = require "luci.util"
    local nixio = require "nixio"
    local sys = require "luci.sys"

    local interface = http.formvalue("interface")
    local filter = http.formvalue("filter") or ""
    local filesize = http.formvalue("filesize") or ""
    local count = http.formvalue("count") or ""
    
    -- 安全验证
    if not (interface and interface:match("^[%w%-_%.]+$") and nixio.fs.access("/sys/class/net/" .. interface)) then
        http.write_json({success = false, message = "无效或不存在的网络接口"})
        return
    end
    
    if filter:match("[;&|$`]") then -- 基础安全过滤
        http.write_json({success = false, message = "过滤器包含非法字符"})
        return
    end

    -- 启动前清理
    action_stop_internal()
    nixio.fs.unlink(CAPTURE_FILE)
    
    local cmd_parts = {
        "/usr/sbin/tcpdump",
        "-i", interface,
        "-U", -- 实时写入，便于监控文件大小
        "-w", CAPTURE_FILE
    }

    if count and count:match("^%d+$") and tonumber(count) > 0 then
        table.insert(cmd_parts, "-c")
        table.insert(cmd_parts, count)
    end
    
    -- 过滤器必须是最后一个参数，并且用单引号包裹，最安全
    if filter ~= "" then
        table.insert(cmd_parts, filter)
    end

    -- 使用环境变量传递大小限制，而不是解析ps，更可靠
    local env = nil
    if filesize and filesize:match("^%d+$") and tonumber(filesize) > 0 then
        env = "TCPDUMP_SIZE_LIMIT=" .. filesize
    end

    -- 使用luci.sys.process.spawn执行，并获取PID
    local pid = sys.process.spawn(cmd_parts, nil, nil, env)

    -- 检查进程是否成功启动
    nixio.nanosleep(200000000) -- 等待 0.2 秒
    if is_pid_running(pid) then
        nixio.fs.writefile(PID_FILE, tostring(pid))
        http.write_json({success = true, message = "TCPDump 启动成功 (PID: " .. pid .. ")"})
    else
        http.write_json({success = false, message = "TCPDump 启动失败，请检查接口或过滤器是否正确"})
    end
end

-- 停止抓包
function action_stop()
    action_stop_internal()
    http.write_json({success = true, message = "抓包已停止"})
end

-- 删除文件
function action_delete()
    action_stop_internal()
    nixio.fs.unlink(CAPTURE_FILE)
    http.write_json({success = true, message = "抓包文件已删除"})
end

-- 下载文件 (逻辑微调，增加错误处理)
function action_download()
    local http = require "luci.http"
    if not nixio.fs.access(CAPTURE_FILE) then
        http.status(404, "Not Found")
        http.prepare_content("text/plain")
        http.write("抓包文件不存在")
        return
    end
    http.setfilehandler(CAPTURE_FILE)
    http.header('Content-Disposition', 'attachment; filename="tcpdump_' .. os.date("%Y%m%d_%H%M%S") .. '.pcap"')
end

-- 新增：控制 broute (桥接流量捕获)
function action_broute()
    local http = require "luci.http"
    local util = require "luci.util"
    local enabled = http.formvalue("enable") == "true"

    if not EBTABLES_INSTALLED then
        http.write_json({success = false, message = "ebtables 未安装"})
        return
    end

    -- 总是先清空规则，确保干净
    util.exec("ebtables -t broute -F")

    if enabled then
        util.exec("ebtables -t broute -A BROUTING -j ACCEPT")
        http.write_json({success = true, message = "桥接流量捕获已开启"})
    else
        http.write_json({success = true, message = "桥接流量捕获已关闭"})
    end
end
