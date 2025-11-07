--
-- LuCI RPC 后端 for tcpdump (安全加固版)
--

local fs = require "nixio.fs"
local sys = require "nixio.sys"

local PID_FILE = "/tmp/tcpdump.pid"
local LOG_FILE = "/tmp/tcpdump.log"
local CAP_FILE = "/tmp/tcpdump.pcap"

-- 安全验证：网络接口
local function validate_interface(ifname)
    if not ifname or ifname == "" then
        return "br-lan"
    end
    if ifname:match("[^a-zA-Z0-9%._%-]") then
        return "br-lan"  -- 非法输入回退
    end
    return ifname
end

-- 安全验证：BPF 过滤器
local function validate_filter(filter)
    if not filter or filter == "" then
        return "port 80"  -- 默认安全过滤器
    end
    -- 仅允许安全字符（字母数字、点、斜杠、冒号、逗号、括号、等号）
    local safe_filter = filter:gsub("[^a-zA-Z0-9%.:/,()=]", "")
    return safe_filter
end

-- 检查进程是否在运行
local function is_running()
    local pid = fs.readfile(PID_FILE)
    if pid and pid:match("^%d+$") then
        return fs.stat("/proc/" .. pid) ~= nil
    end
    return false
end

-- RPC 方法：开始抓包
local function start_capture(interface, filter, filesize)
    if is_running() then
        return { error = "tcpdump is already running." }
    end

    -- 安全验证输入
    local safe_if = validate_interface(interface)
    local safe_filter = validate_filter(filter)

    -- 处理文件大小限制
    local size_opt = ""
    if filesize and tonumber(filesize) and tonumber(filesize) > 0 then
        size_opt = "-C " .. tonumber(filesize)
    end

    -- 构建安全命令
    local command = string.format(
        "tcpdump -i %s %s -U -s 0 -w %s %s >%s 2>&1 & echo $! > %s",
        safe_if,
        size_opt,
        CAP_FILE,
        safe_filter,
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
    local pid = fs.readfile(PID_FILE)
    if pid and pid:match("^%d+$") and is_running() then
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

-- ✅ 正确注册 RPC 接口（与 ACL 匹配）
return {
    start = start_capture,
    stop = stop_capture,
    status = get_status
}
