'use strict';
'require baseclass';
'require form';
'require rpc';
'require ui';
'require network';

//
// LuCI JS 前端 for tcpdump
//

// 定义一个 RPC 调用，指向我们后端的 lua 文件的 'tcpdump' 命名空间
var callTcpdumpStart = rpc.declare({
    object: 'tcpdump',
    method: 'start',
    params: ['interface', 'filter', 'filesize'], // 包含 filesize
    expect: { result: {} }
});

var callTcpdumpStop = rpc.declare({
    object: 'tcpdump',
    method: 'stop',
    expect: { result: {} }
});

var callTcpdumpStatus = rpc.declare({
    object: 'tcpdump',
    method: 'status',
    expect: { result: {} }
});

// 主视图
return baseclass.extend({
    // 页面标题
    title: _('TCPDump'),
    
    // 渲染函数
    render: function(data) {
        var m, s, o;

        // 创建一个表单
        m = new form.Map('tcpdump', _('TCPDump Capture'),
            _('这是一个简单的 tcpdump 前端。抓包文件将保存在 /tmp/tcpdump.pcap。' +
              '你需要使用 SCP 或 WinSCP 手动下载它。'));

        // '设置' 段
        s = m.section(form.NamedSection, 'settings', 'tcpdump');
        s.anonymous = true;

        // 接口选择
        o = s.option(form.Value, 'interface', _('Interface'),
            _('选择要抓包的网络接口。'));
        o.value('br-lan', 'LAN (br-lan)');
        o.value('eth0', 'WAN (eth0)'); 
        o.placeholder = 'br-lan'; // 默认值
        // 动态加载所有接口
        o.load = function(section_id) {
            return network.getDevices().then(function(devices) {
                devices.forEach(function(dev) {
                    o.value(dev.getName(), dev.getName());
                });
            });
        };

        // 过滤器输入框
        o = s.option(form.Value, 'filter', _('Filter'),
            _('BPF 过滤器 (例如: "port 80" 或 "host 192.168.1.100")'));
        o.placeholder = 'port 67 or port 68 or port 80';

        // ⭐️ 新增：文件大小限制
        o = s.option(form.Value, 'filesize', _('Size Limit (MB)'),
            _('当文件达到此大小（单位MB）时自动停止抓包。留空则无限制。'));
        o.datatype = 'uinteger'; // 确保输入的是正整数
        o.placeholder = '10'; // 默认提示 10MB

        // '控制' 段
        s = m.section(form.NamedSection, 'control', 'tcpdump');
        s.anonymous = true;

        // 状态显示
        o = s.option(form.DummyValue, 'status', _('Status'));
        o.raw = true; // 我们将手动设置 HTML
        o.value = '...';
        o.id = 'tcpdump-status'; // 给它一个ID以便更新

        // 开始/停止按钮
        o = s.option(form.Button, '_control', _('Control'));
        o.inputtitle = _('Start Capture');
        o.inputstyle = 'apply'; // 绿色
        o.id = 'btn-start';
        o.onclick = function() {
            var map = this.map;
            var iface = map.data.interface || 'br-lan';
            var filter = map.data.filter || '';
            var filesize = map.data.filesize || null; // ⭐️ 获取文件大小
            
            // ⭐️ 将文件大小传递给后端
            return callTcpdumpStart(iface, filter, filesize).then(function(result) {
                if (result.error) {
                    ui.addNotification(null, E('p', _('Error: ') + result.error));
                } else {
                    ui.addNotification(null, E('p', _('Capture started.')));
                }
                view.self.updateStatus(); // 更新状态
            });
        };

        o = s.option(form.Button, '_stop');
        o.inputtitle = _('Stop Capture');
        o.inputstyle = 'reset'; // 红色
        o.id = 'btn-stop';
        o.onclick = function() {
            return callTcpdumpStop().then(function(result) {
                ui.addNotification(null, E('p', _('Capture stopped and files cleaned.')));
                view.self.updateStatus(); // 更新状态
            });
        };

        // 返回渲染的表单
        return m.render();
    },

    // 在页面加载后运行的函数
    load: function() {
        // L.Poll.add 会定期轮询
        L.Poll.add(this.updateStatus.bind(this), 3);
        return this.updateStatus();
    },

    // 更新状态的函数
    updateStatus: function() {
        var statusEl = document.getElementById('tcpdump-status');
        
        return callTcpdumpStatus().then(function(result) {
            if (result.running) {
                statusEl.innerHTML = '<span style="color:green; font-weight:bold;">' + 
                    _('RUNNING (PID: %h)').format(result.pid) + '</span>';
                document.getElementById('btn-start').disabled = true;
                document.getElementById('btn-stop').disabled = false;
            } else {
                statusEl.innerHTML = '<span style="color:red; font-weight:bold;">' + 
                    _('STOPPED') + '</span>';
                document.getElementById('btn-start').disabled = false;
                document.getElementById('btn-stop').disabled = true;
            }
        });
    }
});
