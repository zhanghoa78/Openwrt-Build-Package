module("luci.controller.tcpdump", package.seeall)

function index()
    entry({"admin", "services", "tcpdump"}, alias("admin", "services", "tcpdump", "status"), _("TCPDump"), 60)
    entry({"admin", "services", "tcpdump", "status"}, template("tcpdump/status"), _("状态"), 1)
    entry({"admin", "services", "tcpdump", "ajax_status"}, call("action_ajax_status"))
    entry({"admin", "services", "tcpdump", "interfaces"}, call("action_get_interfaces"))
    entry({"admin", "services", "tcpdump", "start"}, call("action_start"))
    entry({"admin", "services", "tcpdump", "stop"}, call("action_stop"))
end

-- 获取网络接口列表
function action_get_interfaces()
    local util = require "luci.util"
    local sys = require "luci.sys"
    local interfaces = {}
    
    -- 使用luci.sys获取网络设备
    for _, iface in ipairs(sys.net.devices()) do
        if iface ~= "lo" then  -- 排除回环接口
            table.insert(interfaces, iface)
        end
    end
    
    -- 如果上面的方法获取不到，使用ip命令
    if #interfaces == 0 then
        local ip_output = util.exec("ip link show 2>/dev/null")
        for iface in ip_output:gmatch("(%d+): ([%w%-]+):") do
            local ifname = iface:match("(%d+): ([%w%-]+):")
            if ifname and ifname ~= "lo" then
                table.insert(interfaces, ifname)
            end
        end
    end
    
    -- 去重并排序
    local seen = {}
    local unique_interfaces = {}
    for _, iface in ipairs(interfaces) do
        if not seen[iface] then
            seen[iface] = true
            table.insert(unique_interfaces, iface)
        end
    end
    table.sort(unique_interfaces)
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(unique_interfaces)
end

-- 检查 tcpdump 状态
function action_ajax_status()
    local util = require "luci.util"
    local pid = util.exec("ps | grep 'tcpdump.*-w /tmp/tcpdump.pcap' | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null"):match("%d+")
    local running = pid ~= nil
    
    luci.http.prepare_content("application/json")
    luci.http.write_json({ 
        running = running, 
        pid = pid
    })
end

-- 启动抓包
function action_start()
    local http = require "luci.http"
    local util = require "luci.util"
    
    local interface = http.formvalue("interface") or "br-lan"
    local filter = http.formvalue("filter") or ""
    local filesize = http.formvalue("filesize") or ""
    
    local result = { success = false }
    
    -- 先检查是否已在运行
    local current_pid = util.exec("ps | grep 'tcpdump.*-w /tmp/tcpdump.pcap' | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null"):match("%d+")
    if current_pid then
        result.message = "抓包已在运行 (PID: " .. current_pid .. ")"
        luci.http.prepare_content("application/json")
        return luci.http.write_json(result)
    end
    
    -- 停止任何可能正在运行的实例
    os.execute("killall tcpdump 2>/dev/null")
    util.exec("sleep 1")
    
    -- 构建命令
    local cmd = "tcpdump -i " .. interface .. " -w /tmp/tcpdump.pcap"
    
    -- 添加过滤器
    if filter and filter ~= "" then
        cmd = cmd .. " " .. filter
    end
    
    -- 添加文件大小限制
    if filesize and filesize ~= "" then
        local num = tonumber(filesize)
        if num and num > 0 then
            cmd = cmd .. " -C " .. tostring(math.floor(num))
        end
    end
    
    -- 在后台运行
    cmd = cmd .. " 2>/dev/null &"
    
    -- 执行命令
    local exitcode = os.execute(cmd)
    
    if exitcode == 0 or exitcode == true then
        -- 等待进程启动
        util.exec("sleep 2")
        
        -- 再次检查进程是否在运行
        local new_pid = util.exec("ps | grep 'tcpdump.*-w /tmp/tcpdump.pcap' | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null"):match("%d+")
        if new_pid then
            result.success = true
            result.message = "抓包已启动"
            result.pid = new_pid
        else
            result.message = "进程启动失败"
        end
    else
        result.message = "启动命令执行失败"
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end

-- 停止抓包
function action_stop()
    local util = require "luci.util"
    local result = { success = false }
    
    -- 使用killall停止所有tcpdump进程
    os.execute("killall tcpdump 2>/dev/null")
    util.exec("sleep 2")
    
    -- 验证是否停止
    local pid = util.exec("ps | grep 'tcpdump.*-w /tmp/tcpdump.pcap' | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null"):match("%d+")
    
    if not pid then
        result.success = true
        result.message = "抓包已停止"
    else
        -- 如果还有进程，尝试强制杀死
        os.execute("killall -9 tcpdump 2>/dev/null")
        util.exec("sleep 1")
        local pid_after = util.exec("ps | grep 'tcpdump.*-w /tmp/tcpdump.pcap' | grep -v grep | head -1 | awk '{print $1}' 2>/dev/null"):match("%d+")
        if not pid_after then
            result.success = true
            result.message = "抓包已强制停止"
        else
            result.message = "停止失败"
        end
    end
    
    luci.http.prepare_content("application/json")
    luci.http.write_json(result)
end
