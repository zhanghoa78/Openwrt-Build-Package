--
-- LuCI RPC 后端 for tcpdump
--

local fs = require "nixio.fs"
local sys = require "nixio.sys"

local PID_FILE = "/tmp/tcpdump.pid"
local LOG_FILE = "/tmp/tcpdump.log"
local CAP_FILE = "/tmp/tcpdump.pcap"

-- 帮助函数：检查进程是否在运行
local function is_running()
    local pid = fs.readfile(PID_FILE)
    if pid then
        pid = tonumber(pid)
        -- 检查 /proc/[pid] 目录是否存在
        return fs.stat("/proc/" .. pid) ~= nil
    end
    return false
end

-- RPC 方法：开始抓包
-- @param interface: (string) 网络接口, e.g., 'br-lan'
-- @param filter: (string) BPF 过滤器, e.g., 'port 80'
local function start_capture(interface, filter)
    if is_running() then
        return { error = "tcpdump is already running." }
    end

    -- !! 安全警告：这是一个非常基础的输入检查 !!
    -- !! 在生产环境中，需要更严格的过滤来防止命令注入 !!
    if not interface or not interface:match("^[a-zA-Z0-9%-%._]+$") then
        interface = "br-lan" -- 默认值
    end

    if not filter or filter == "" then
        filter = "''" -- 空过滤器
    else
        -- 基础的转义，防止一些简单的注入
        filter = "'" .. filter:gsub("'", "'\\''") .. "'"
    end
    
    local command = string.format(
        "tcpdump -i %s -U -s 0 -w %s %s >%s 2>&1 & echo $! > %s",
        interface,
        CAP_FILE,
        filter,
        LOG_FILE,
        PID_FILE
    )

    -- 执行命令
    local ok, code = sys.call(command)
    if ok then
        return { success = true, command = command }
    else
        return { error = "Failed to start tcpdump", code = code }
    end
end

-- RPC 方法：停止抓包
local function stop_capture()
    if not is_running() then
        return { success = true, message = "Not running." }
    end

    local pid = fs.readfile(PID_FILE)
    if pid then
        -- 发送 SIGTERM 信号
        sys.call("kill " .. pid)
    end

    -- 清理文件
    fs.unlink(PID_FILE)
    fs.unlink(CAP_FILE)
    fs.unlink(LOG_FILE)

    return { success = true }
end

-- RPC 方法：获取状态
local function get_status()
    if is_running() then
        return { running = true, pid = fs.readfile(PID_FILE) }
    else
        return { running = false }
    end
end

-- 将本地函数暴露给 RPC
return {
    start = start_capture,
    stop = stop_capture,
    status = get_status
}
