module("luci.controller.tcpdump", package.seeall)

function index()
    if not nixio.fs.access("/usr/sbin/tcpdump") then
        return
    end
    
    entry({"admin", "services", "tcpdump"}, firstchild(), _("TCPDump"), 60).dependent = false
    entry({"admin", "services", "tcpdump", "status"}, template("tcpdump/status"), _("Status"), 1)
    entry({"admin", "services", "tcpdump", "ajax_status"}, call("action_ajax_status"))
    entry({"admin", "services", "tcpdump", "start"}, call("action_start"))
    entry({"admin", "services", "tcpdump", "stop"}, call("action_stop"))
    entry({"admin", "services", "tcpdump", "download"}, call("action_download"))
end

function action_ajax_status()
    local util = require "luci.util"
    local http = require "luci.http"
    
    local pid = util.exec("pgrep -f 'tcpdump.*-w /tmp/tcpdump.pcap' 2>/dev/null"):match("%d+")
    local running = pid ~= nil
    
    local result = { 
        running = running, 
        pid = pid 
    }
    
    http.prepare_content("application/json")
    http.write_json(result)
end

function action_start()
    local http = require "luci.http"
    local util = require "luci.util"
    
    local interface = http.formvalue("interface") or "br-lan"
    local filter = http.formvalue("filter") or ""
    local filesize = http.formvalue("filesize") or ""
    
    local result = { success = false, message = "" }
    
    -- Stop any running instances
    os.execute("killall tcpdump 2>/dev/null")
    util.exec("sleep 1")
    
    -- Build command
    local cmd = "tcpdump -i " .. interface .. " -w /tmp/tcpdump.pcap"
    
    if filter and filter ~= "" then
        cmd = cmd .. " " .. filter
    end
    
    if filesize and filesize ~= "" then
        local num = tonumber(filesize)
        if num and num > 0 then
            cmd = cmd .. " -C " .. tostring(math.floor(num))
        end
    end
    
    cmd = cmd .. " 2>/dev/null &"
    
    local exitcode = os.execute(cmd)
    
    if exitcode == 0 or exitcode == true then
        util.exec("sleep 2")
        local new_pid = util.exec("pgrep -f 'tcpdump.*-w /tmp/tcpdump.pcap' 2>/dev/null"):match("%d+")
        if new_pid then
            result.success = true
            result.message = "Capture started (PID: " .. new_pid .. ")"
            result.pid = new_pid
        else
            result.message = "Process failed to start"
        end
    else
        result.message = "Command execution failed"
    end
    
    http.prepare_content("application/json")
    http.write_json(result)
end

function action_stop()
    local util = require "luci.util"
    local http = require "luci.http"
    local result = { success = false, message = "" }
    
    os.execute("killall tcpdump 2>/dev/null")
    util.exec("sleep 2")
    
    local pid = util.exec("pgrep -f 'tcpdump.*-w /tmp/tcpdump.pcap' 2>/dev/null"):match("%d+")
    
    if not pid then
        result.success = true
        result.message = "Capture stopped"
    else
        result.message = "Stop failed"
    end
    
    http.prepare_content("application/json")
    http.write_json(result)
end

function action_download()
    local http = require "luci.http"
    local nixio = require "nixio"
    
    local filename = "/tmp/tcpdump.pcap"
    
    if nixio.fs.access(filename) then
        http.header('Content-Type', 'application/vnd.tcpdump.pcap')
        http.header('Content-Disposition', 'attachment; filename="tcpdump_capture.pcap"')
        
        local file = nixio.fs.readfile(filename)
        if file then
            http.write(file)
        end
    else
        http.status(404, "File not found")
    end
end
