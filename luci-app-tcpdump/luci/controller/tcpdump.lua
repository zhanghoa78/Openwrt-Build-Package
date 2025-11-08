module("luci.controller.tcpdump", package.seeall)

function index()
    entry({"admin", "network", "tcpdump"}, template("tcpdump/index"), _("TCPDump"), 60)
end
