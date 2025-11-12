<%+header%>

<!-- 页面样式 -->
<style type="text/css">
/* 状态指示器样式 */
.status-indicator-general {
    padding: 5px 10px;
    border-radius: 4px;
    font-weight: bold;
}

/* 确保信息元素不被挤压 */
#interface-info, #file-size-info {
    white-space: nowrap;
    margin-left: 10px;
    padding: 3px 8px;
    background-color: #f5f5f5;
    border-radius: 3px;
    border: 1px solid #e0e0e0;
}

/* 端口选择按钮样式 */
.filter-preset-btn, .filter-preset-group-btn {
    /* 未选中状态 - 浅色 */
    background-color: #1014f359;
    color: #666666;
    border: 1px solid #d0d0d0;
    transition: all 0.2s ease;
    padding: 8px 12px;
    border-radius: 4px;
}

.filter-preset-btn.active, .filter-preset-group-btn.active,
.filter-preset-btn.cbi-button-highlight, .filter-preset-group-btn.cbi-button-highlight {
    /* 选中状态 - 深色 */
    background-color: #080ce2c4;
    color: #ffffff;
    border: 1px solid #d0d0d0;
    box-shadow: 0 3px 6px rgba(0,0,0,0.15);
    font-weight: bold;
}

/* 响应式调整 */
@media (max-width: 768px) {
    #status-text {
        display: block;
        margin-bottom: 5px;
    }
    
    #interface-info, #file-size-info {
        margin-left: 0;
        margin-right: 5px;
        margin-bottom: 5px;
    }
}
</style>

<div class="cbi-map">
	<h2 name="content"><%:TCPDump 数据包捕获%></h2>
	<div class="cbi-map-descr">
		<%:简单的 tcpdump 数据包捕获网页界面。%><br>
		<%:捕获文件保存在 /tmp/tcpdump.pcap。%>
	</div>

	<fieldset class="cbi-section">
		<legend><%:捕获设置%></legend>
		
		<div class="cbi-value">
			<label class="cbi-value-title"><%:网络接口%></label>
			<div class="cbi-value-field">
				<div style="display: flex; align-items: center; gap: 10px;"> <!-- 使用Flexbox保持水平排列 -->
					<select id="interface" class="cbi-input-select" style="flex-grow: 1;">
						<option value=""><%:正在加载接口...%></option>
					</select>
					<button id="btn-refresh" class="cbi-button" onclick="refreshInterfaces()">
						<%:刷新接口%>
					</button>
				</div>
			</div>
		</div>

		<div class="cbi-value">
			<label class="cbi-value-title"><%:网络数据过滤器%></label>
			<div class="cbi-value-field">
				<div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
					<input type="text" id="filter" class="cbi-input-text" style="flex-grow: 1;"
						   placeholder="输入 BPF 过滤器，例如: port 80 or port 443" />
					<button type="button" class="cbi-button" onclick="showAdvancedFilterDialog()">
						<%:高级过滤器%>
					</button>
				</div>
				
				<div class="cbi-value-description"><%:快速选择端口:%></div>
				<div style="display: flex; flex-wrap: wrap; gap: 5px; margin-top: 5px; margin-bottom: 10px;">
					<!-- 组合端口选择按钮 -->
					<button type="button" class="cbi-button cbi-button-action filter-preset-group-btn" data-group="web">Web (HTTP/S)</button>
					<button type="button" class="cbi-button cbi-button-action filter-preset-group-btn" data-group="dhcp">DHCP (S/C)</button>
					<button type="button" class="cbi-button cbi-button-action filter-preset-group-btn" data-group="dns">DNS</button>
					<!-- 如果需要，可以保留或添加其他独立的常用端口 -->
					<button type="button" class="cbi-button cbi-button-action filter-preset-btn" data-port="22">SSH</button>
					<button type="button" class="cbi-button cbi-button-action filter-preset-btn" data-port="123">NTP</button>
				</div>
				
				<div class="cbi-value-description">
					<%:使用 BPF 语法，支持多个端口: port 80 or port 443。%><br>
					<%:留空捕获所有流量。%>
				</div>
			</div>
		</div>

		<div class="cbi-value">
			<label class="cbi-value-title"><%:包数量限制%></label>
			<div class="cbi-value-field">
				<input type="number" id="count" class="cbi-input-text" placeholder="1000" min="1" max="100000" />
				<div class="cbi-value-description">
					<%:捕获指定数量的包后自动停止，留空表示无限制%>
				</div>
			</div>
		</div>
	</fieldset>

	<fieldset class="cbi-section">
		<legend><%:状态与控制%></legend>
		
		<div class="cbi-value">
			<label class="cbi-value-title"><%:状态%></label>
			<div class="cbi-value-field">
				<div style="display: flex; align-items: center; flex-wrap: wrap;"> <!-- flex-wrap 以防内容过多挤压 -->
					<span id="status-text" class="cbi-value-description status-indicator-general">
						<%:加载中...%>
					</span>
					<span id="interface-info" class="cbi-value-description" style="display: none; margin-left: 10px;"></span>
					<span id="file-size-info" class="cbi-value-description" style="display: none; margin-left: 10px;"></span> 
                    <!-- 新增文件大小显示元素 -->
				</div>
			</div>
		</div>

		<div class="cbi-value cbi-value-last">
			<label class="cbi-value-title"><%:操作%></label>
			<div class="cbi-value-field">
				<div class="cbi-button-group"> <!-- 使用cbi-button-group可能提供更好的样式 -->
					<button id="btn-start" class="cbi-button cbi-button-apply" onclick="startCapture()">
						<%:开始捕获%>
					</button>
					<button id="btn-stop" class="cbi-button cbi-button-reset" onclick="stopCapture()" disabled>
						<%:停止捕获%>
					</button>
					<button id="btn-download" class="cbi-button cbi-button-action" onclick="downloadCapture()" disabled>
						<%:下载文件%>
					</button>
					<button id="btn-delete" class="cbi-button cbi-button-negative" onclick="deleteCapture()" disabled>
						<%:删除文件%>
					</button>
				</div>
			</div>
		</div>
	</fieldset>

	<fieldset class="cbi-section">
		<legend><%:使用提示%></legend>
		<div class="cbi-section-descr">
			<ul class="cbi-value-description"> <!-- 调整为使用cbi-value-description包装列表 -->
				<li><%:快捷键: Ctrl+Enter 开始捕获, Ctrl+Esc 停止捕获%></li>
				<li><%:点击端口按钮快速添加过滤器%></li>
				<li><%:文件保存在 /tmp/tcpdump.pcap，重启后会丢失%></li>
				<li><%:使用 Wireshark 或 tcpdump 命令分析下载的 .pcap 文件%></li>
			</ul>
		</div>
	</fieldset>
</div>

<script type="text/javascript">
//<![CDATA[

// ------------------------------------------------
// 全局状态和配置
// ------------------------------------------------
var tcpdumpState = {
    isUpdating: false,
    lastUpdate: 0,
    updateInterval: 3000
};

// ------------------------------------------------
// 工具函数
// ------------------------------------------------
function formatFileSize(bytes) {
    if (bytes === 0 || !bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ------------------------------------------------
// 页面状态显示系统
// ------------------------------------------------
function showNotification(message, type) {
    var statusArea = document.getElementById('status-message-area');
    if (!statusArea) {
        // 如果状态区域不存在，创建一个
        statusArea = document.createElement('div');
        statusArea.id = 'status-message-area';
        statusArea.className = 'cbi-section';
        statusArea.style.cssText = `
            margin-bottom: 15px;
            padding: 10px;
            border-radius: 4px;
            transition: background-color 0.3s ease;
        `;
        
        var mainContent = document.querySelector('.cbi-map');
        if (mainContent) {
            mainContent.insertBefore(statusArea, mainContent.firstChild);
        }
    }
    
    // 设置状态区域样式和内容
    statusArea.className = 'cbi-section ' + 
        (type === 'error' ? 'cbi-section-error' : type === 'success' ? 'cbi-section-success' : 'cbi-section-info');
    
    statusArea.innerHTML = '<p class="cbi-value-title">' + 
        (type === 'error' ? '<%:错误%>' : type === 'success' ? '<%:成功%>' : '<%:信息%>') + 
        '</p><p class="cbi-value-description">' + message + '</p>';
    
    // 5秒后自动清除消息（如果没有新消息）
    clearTimeout(window.statusMessageTimeout);
    window.statusMessageTimeout = setTimeout(function() {
        statusArea.innerHTML = '';
    }, 5000);
}

// ------------------------------------------------
// 端口选择器逻辑 (大幅修改以支持组合按钮)
// ------------------------------------------------
function setupPortSelector() {
    var filterInput = document.getElementById('filter');
    
    // 定义端口组及其对应的端口
    var portGroups = {
        'web': ['80', '443'],
        'dhcp': ['67', '68'],
        'dns': ['53']
    };

    // 获取所有独立端口按钮 (如 SSH, NTP)
    var singlePortButtons = document.querySelectorAll('.filter-preset-btn');
    // 获取所有组合端口按钮
    var groupPortButtons = document.querySelectorAll('.filter-preset-group-btn');
    
    var currentFilterPorts = new Set();

    function parseFilterInput() {
        currentFilterPorts.clear();
        var filterValue = filterInput.value.trim();
        if (filterValue) {
            var matches = filterValue.matchAll(/port\s+(\d+)\b/g); 
            for (const match of matches) {
                currentFilterPorts.add(match[1]);
            }
        }
    }

    function updateFilterInput() {
        var portsArray = Array.from(currentFilterPorts);
        if (portsArray.length > 0) {
            portsArray.sort((a,b) => parseInt(a) - parseInt(b));
            filterInput.value = 'port ' + portsArray.join(' or port ');
        } else {
            filterInput.value = '';
        }
        filterInput.dispatchEvent(new Event('input', { bubbles: true }));
    }

    function updatePresetButtons() {
        parseFilterInput();
        
        singlePortButtons.forEach(function(button) {
            var port = button.dataset.port;
            if (currentFilterPorts.has(port)) {
                button.classList.add('active', 'cbi-button-highlight');
            } else {
                button.classList.remove('active', 'cbi-button-highlight');
            }
        });

        groupPortButtons.forEach(function(button) {
            var groupKey = button.dataset.group;
            var portsInGroup = portGroups[groupKey];
            
            var allPortsInGroupSelected = portsInGroup.every(p => currentFilterPorts.has(p));

            if (allPortsInGroupSelected) {
                button.classList.add('active', 'cbi-button-highlight');
            } else {
                button.classList.remove('active', 'cbi-button-highlight');
            }
        });
    }

    singlePortButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            var port = this.dataset.port;
            if (currentFilterPorts.has(port)) {
                currentFilterPorts.delete(port);
            } else {
                currentFilterPorts.add(port);
            }
            updateFilterInput();
            updatePresetButtons();
        });
    });

    groupPortButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            var groupKey = this.dataset.group;
            var portsInGroup = portGroups[groupKey];
            
            var allPortsSelected = portsInGroup.every(p => currentFilterPorts.has(p));
            
            if (allPortsSelected) {
                portsInGroup.forEach(p => currentFilterPorts.delete(p));
            } else {
                portsInGroup.forEach(p => currentFilterPorts.delete(p));
                portsInGroup.forEach(p => currentFilterPorts.add(p));
            }
            updateFilterInput();
            updatePresetButtons();
        });
    });

    filterInput.addEventListener('input', updatePresetButtons);
    
    updatePresetButtons();

    filterInput.addEventListener('focus', function() {
        this.select();
    });
}
// ------------------------------------------------
// 高级过滤器构建器 (优化版)
// ------------------------------------------------
function showAdvancedFilterDialog() {
    var filterInput = document.getElementById('filter');
    
    // 解析当前过滤器值以预填充高级过滤表单
    function parseCurrentFilter() {
        var currentFilter = filterInput.value.trim();
        var result = { host: '', protocol: '', port: '', network: '' };
        
        if (!currentFilter) return result;
        
        // 简单解析当前过滤器值（实际实现可能需要更复杂的解析逻辑）
        if (currentFilter.match(/\bhost\s+([^\s]+)/i)) {
            result.host = currentFilter.match(/\bhost\s+([^\s]+)/i)[1];
        }
        
        ['tcp', 'udp', 'icmp', 'arp'].forEach(protocol => {
            if (currentFilter.match(new RegExp(`\\b${protocol}\\b`, 'i'))) {
                result.protocol = protocol;
            }
        });
        
        if (currentFilter.match(/\bportrange\s+([^\s]+)/i)) {
            result.port = currentFilter.match(/\bportrange\s+([^\s]+)/i)[1];
        } else if (currentFilter.match(/\bport\s+([^\s,]+)/i)) {
            // 提取单个或多个端口
            var ports = currentFilter.match(/\bport\s+([^\s,]+)/ig) || [];
            ports = ports.map(p => p.replace(/^port\s+/i, ''));
            result.port = ports.join(', ');
        }
        
        if (currentFilter.match(/\bnet\s+([^\s]+)/i)) {
            result.network = currentFilter.match(/\bnet\s+([^\s]+)/i)[1];
        }
        
        return result;
    }
    
    var currentFilterValues = parseCurrentFilter();
    
    // 创建或获取高级过滤器区域
    var filterArea = document.getElementById('advanced-filter-area');
    if (!filterArea) {
        filterArea = document.createElement('div');
        filterArea.id = 'advanced-filter-area';
        filterArea.className = 'cbi-section';
        
        var mainContent = document.querySelector('.cbi-map');
        if (mainContent) {
            // 将高级过滤器区域插入到适当位置
            var statusSection = document.querySelector('fieldset.cbi-section:has(legend)');
            if (statusSection) {
                mainContent.insertBefore(filterArea, statusSection.nextSibling);
            } else {
                mainContent.appendChild(filterArea);
            }
        }
    }
    
    // 确保区域可见
    filterArea.style.display = 'block';
    
    var dialogHtml = `
<div style="background: white; padding: 24px; border-radius: 8px; width: 100%; box-sizing: border-box;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #eee; padding-bottom: 10px;">
                    <h3 style="margin: 0; color: #333;"><%:高级过滤器构建器%></h3>
                    <button type="button" class="cbi-button" style="padding: 5px 10px;" onclick="closeAdvancedFilter()">
                        &times;
                    </button>
                </div>
                
                <!-- 过滤条件预览区域 -->
                <div style="background-color: #f5f5f5; border-radius: 4px; padding: 12px; margin-bottom: 20px; font-family: monospace;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
                        <strong style="color: #555;"><%:当前过滤器:%></strong>
                        <button type="button" id="btn-clear-filter" class="cbi-button" style="padding: 2px 8px; font-size: 0.9em;">
                            <%:清除%>
                        </button>
                    </div>
                    <div id="filter-preview" style="color: #333; min-height: 20px; word-break: break-all;">
                        ${currentFilterValues.host || currentFilterValues.protocol || currentFilterValues.port || currentFilterValues.network 
                            ? filterInput.value : '<%:无过滤条件%>'}
                    </div>
                </div>
                
                <!-- 输入字段区域 -->
                <div style="display: grid; grid-template-columns: 1fr; gap: 16px;">
                    <div class="cbi-value" style="margin-bottom: 0;">
                        <label class="cbi-value-title" style="margin-bottom: 6px; display: inline-block;"><%:主机/IP地址:%></label>
                        <div class="cbi-value-field">
                            <input type="text" id="adv-host" class="cbi-input-text" style="width: 100%; padding: 8px; border-radius: 4px;" 
                                placeholder="例如: 192.168.1.1 或 example.com" value="${currentFilterValues.host || ''}">
                            <div style="font-size: 0.9em; color: #666; margin-top: 4px;"><%:指定要过滤的主机或域名%></div>
                        </div>
                    </div>
                    
                    <div class="cbi-value" style="margin-bottom: 0;">
                        <label class="cbi-value-title" style="margin-bottom: 6px; display: inline-block;"><%:协议:%></label>
                        <div class="cbi-value-field">
                            <select id="adv-protocol" class="cbi-input-select" style="width: 100%; padding: 8px; border-radius: 4px;">
                                <option value=""><%:所有协议%></option>
                                <option value="tcp" ${currentFilterValues.protocol === 'tcp' ? 'selected' : ''}>TCP</option>
                                <option value="udp" ${currentFilterValues.protocol === 'udp' ? 'selected' : ''}>UDP</option>
                                <option value="icmp" ${currentFilterValues.protocol === 'icmp' ? 'selected' : ''}>ICMP</option>
                                <option value="arp" ${currentFilterValues.protocol === 'arp' ? 'selected' : ''}>ARP</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="cbi-value" style="margin-bottom: 0;">
                        <label class="cbi-value-title" style="margin-bottom: 6px; display: inline-block;"><%:端口:%></label>
                        <div class="cbi-value-field">
                            <input type="text" id="adv-port" class="cbi-input-text" style="width: 100%; padding: 8px; border-radius: 4px;" 
                                placeholder="例如: 80, 443 或 1-1024" value="${currentFilterValues.port || ''}">
                            <div style="font-size: 0.9em; color: #666; margin-top: 4px;"><%:使用逗号分隔多个端口，或使用连字符指定端口范围%></div>
                        </div>
                    </div>
                    
                    <div class="cbi-value" style="margin-bottom: 0;">
                        <label class="cbi-value-title" style="margin-bottom: 6px; display: inline-block;"><%:网络段:%></label>
                        <div class="cbi-value-field">
                            <input type="text" id="adv-network" class="cbi-input-text" style="width: 100%; padding: 8px; border-radius: 4px;" 
                                placeholder="例如: 192.168.1.0/24" value="${currentFilterValues.network || ''}">
                            <div style="font-size: 0.9em; color: #666; margin-top: 4px;"><%:使用CIDR表示法指定网络范围%></div>
                        </div>
                    </div>
                </div>
                
                <!-- 按钮区域 -->
                <div style="display: flex; justify-content: flex-end; gap: 12px; margin-top: 24px; padding-top: 16px; border-top: 1px solid #eee;">
                    <button type="button" class="cbi-button" onclick="closeAdvancedFilter()"><%:取消%></button>
                    <button type="button" class="cbi-button" id="btn-reset-filter" style="margin-right: auto;"><%:重置%></button>
                    <button type="button" class="cbi-button cbi-button-apply" onclick="applyAdvancedFilter()"><%:应用%></button>
                </div>
            </div>
        </div>
    `;
    
    // 将内容设置到页面中的高级过滤器区域
    filterArea.innerHTML = dialogHtml;
    
    // 更新过滤器预览
    function updateFilterPreview() {
        var host = document.getElementById('adv-host').value;
        var protocol = document.getElementById('adv-protocol').value;
        var port = document.getElementById('adv-port').value;
        var network = document.getElementById('adv-network').value;
        
        var filterParts = [];
        
        if (host) {
            filterParts.push('host ' + host);
        }
        
        if (protocol) {
            filterParts.push(protocol);
        }
        
        if (port) {
            if (port.includes('-')) {
                filterParts.push('portrange ' + port);
            } else if (port.includes(',')) {
                var ports = port.split(',').map(p => 'port ' + p.trim()).join(' or ');
                filterParts.push('(' + ports + ')');
            } else {
                filterParts.push('port ' + port);
            }
        }
        
        if (network) {
            filterParts.push('net ' + network);
        }
        
        var finalFilter = filterParts.join(' and ');
        document.getElementById('filter-preview').textContent = finalFilter || '<%:无过滤条件%>';
    }
    
    // 添加输入事件监听器以实时更新预览
    document.getElementById('adv-host').addEventListener('input', updateFilterPreview);
    document.getElementById('adv-protocol').addEventListener('change', updateFilterPreview);
    document.getElementById('adv-port').addEventListener('input', updateFilterPreview);
    document.getElementById('adv-network').addEventListener('input', updateFilterPreview);
    
    // 清除所有过滤条件
    document.getElementById('btn-clear-filter').addEventListener('click', function() {
        document.getElementById('adv-host').value = '';
        document.getElementById('adv-protocol').value = '';
        document.getElementById('adv-port').value = '';
        document.getElementById('adv-network').value = '';
        updateFilterPreview();
    });
    
    // 重置按钮功能
    document.getElementById('btn-reset-filter').addEventListener('click', function() {
        document.getElementById('adv-host').value = currentFilterValues.host || '';
        document.getElementById('adv-protocol').value = currentFilterValues.protocol || '';
        document.getElementById('adv-port').value = currentFilterValues.port || '';
        document.getElementById('adv-network').value = currentFilterValues.network || '';
        updateFilterPreview();
    });
    
    // 点击背景关闭弹窗 (修复：使用filterArea而不是未定义的dialog)
    filterArea.addEventListener('click', function(e) {
        if (e.target === filterArea) {
            closeAdvancedFilter();
        }
    });
    
    // ESC键关闭弹窗
    document.addEventListener('keydown', function escapeHandler(e) {
        if (e.key === 'Escape') {
            closeAdvancedFilter();
            document.removeEventListener('keydown', escapeHandler);
        }
    });
    
    // 初始化时更新预览
    updateFilterPreview();
}

// 修复：将closeAdvancedFilter移到全局作用域
function closeAdvancedFilter() {
    var filterArea = document.getElementById('advanced-filter-area');
    if (filterArea) {
        filterArea.style.display = 'none';
    }
}

// 修复：将applyAdvancedFilter移到全局作用域
function applyAdvancedFilter() {
    var filterInput = document.getElementById('filter');
    var host = document.getElementById('adv-host').value;
    var protocol = document.getElementById('adv-protocol').value;
    var port = document.getElementById('adv-port').value;
    var network = document.getElementById('adv-network').value;
    
    var filterParts = [];
    
    if (host) {
        filterParts.push('host ' + host);
    }
    
    if (protocol) {
        filterParts.push(protocol);
    }
    
    if (port) {
        if (port.includes('-')) {
            filterParts.push('portrange ' + port);
        } else if (port.includes(',')) {
            var ports = port.split(',').map(p => 'port ' + p.trim()).join(' or ');
            filterParts.push('(' + ports + ')');
        } else {
            filterParts.push('port ' + port);
        }
    }
    
    if (network) {
        filterParts.push('net ' + network);
    }
    
    var finalFilter = filterParts.join(' and ');
    filterInput.value = finalFilter;
    filterInput.dispatchEvent(new Event('input', { bubbles: true }));
    
    // 在页面状态中显示过滤器应用成功
    showNotification('<%:过滤器已应用%>', 'success');
    
    closeAdvancedFilter();
}

// ------------------------------------------------
// 接口管理
// ------------------------------------------------
function loadInterfaces() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '<%=url("admin/services/tcpdump/interfaces")%>', true);
    xhr.timeout = 10000;
    
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            var select = document.getElementById('interface');
            
            if (xhr.status === 200) {
                try {
                    var interfaces = JSON.parse(xhr.responseText);
                    
                    if (!interfaces || interfaces.length === 0) {
                        select.innerHTML = '<option value=""><%:未找到网络接口%></option>';
                        return;
                    }
                    
                    select.innerHTML = '';
                    var brLanExists = interfaces.includes('br-lan');
                    
                    interfaces.forEach(function(iface) {
                        var option = document.createElement('option');
                        option.value = iface;
                        
                        if (iface === 'br-lan') {
                            option.textContent = 'br-lan (<%:默认%>)';
                        } else {
                            option.textContent = iface;
                        }
                        
                        select.appendChild(option);
                    });
                    
                    if (brLanExists) {
                        select.value = 'br-lan';
                    } else if (interfaces.length > 0) {
                        select.value = interfaces[0];
                    }
                    
                } catch(e) {
                    console.error('<%:加载接口时出错 (JSON解析失败)%>:', e);
                    select.innerHTML = '<option value=""><%:加载接口失败%></option>';
                }
            } else {
                console.error('<%:加载接口失败，状态码:%>', xhr.status);
                select.innerHTML = '<option value=""><%:加载接口失败 (HTTP %> ' + xhr.status + ')</option>';
            }
        }
    };
    
    xhr.ontimeout = function() {
        console.error('<%:加载接口请求超时%>');
    };
    
    xhr.send();
}

// ------------------------------------------------
// 输入验证
// ------------------------------------------------
function validateInputs() {
    var interfaceVal = document.getElementById('interface');
    var selectedInterface = interfaceVal.value;
    
    var filter = document.getElementById('filter').value;
    var count = document.getElementById('count').value;
    
    var errors = [];
    
    if (!selectedInterface || selectedInterface === "") {
        errors.push('<%:请选择网络接口%>');
    }
    
    if (filter) {
        var dangerousChars = /[;&|`$\\]/;
        if (dangerousChars.test(filter)) {
            errors.push('<%:过滤器中包含不安全的字符%>');
        }
    }
    
    if (count) {
        var packetCount = parseInt(count);
        if (isNaN(packetCount) || packetCount < 1 || packetCount > 100000) {
            errors.push('<%:包数量必须在 1-100000 之间%>');
        }
    }
    
    return errors;
}

// ------------------------------------------------
// 状态管理
// ------------------------------------------------
function updateStatus() {
    if (tcpdumpState.isUpdating) return;
    
    var now = Date.now();
    if (now - tcpdumpState.lastUpdate < 1000) return;
    
    tcpdumpState.isUpdating = true;
    tcpdumpState.lastUpdate = now;
    
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '<%=url("admin/services/tcpdump/ajax_status")%>', true);
    
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            tcpdumpState.isUpdating = false;
            
            if (xhr.status === 200) {
                try {
                    var data = JSON.parse(xhr.responseText);
                    updateUI(data);
                } catch(e) {
                    console.error('<%:更新状态时出错:%>', e);
                    showStatusError('<%:状态数据解析失败%>');
                }
            } else {
                console.error('<%:状态请求失败，状态码:%>', xhr.status);
                showStatusError('<%:状态请求失败 (HTTP %> ' + xhr.status + ')');
            }
        }
    };
    
    xhr.send();
}

function showStatusError(message) {
    // 使用统一的页面状态显示系统
    showNotification('<%:错误:%> ' + message, 'error');
}

// ------------------------------------------------
// UI 更新函数 (新增文件大小显示逻辑)
// ------------------------------------------------
function updateUI(data) {
    var statusEl = document.getElementById('status-text');
    var interfaceInfoEl = document.getElementById('interface-info');
    var fileSizeInfoEl = document.getElementById('file-size-info'); // 获取文件大小显示元素
    var startBtn = document.getElementById('btn-start');
    var stopBtn = document.getElementById('btn-stop');
    var downloadBtn = document.getElementById('btn-download');
    var deleteBtn = document.getElementById('btn-delete');
    
    if (!statusEl) return;
    
    var isRunning = data.running === true;
    var fileExists = data.file_exists === true;
    var fileSize = data.file_size || 0; // 获取文件大小，如果不存在则默认为0
    
    // 重置所有信息显示
    interfaceInfoEl.style.display = 'none';
    fileSizeInfoEl.style.display = 'none';
    
    if (isRunning) {
        // 设置状态文本 - 在状态栏中显示详细信息
        statusEl.className = 'cbi-value-description status-indicator-general success';
        statusEl.textContent = 'TCPDump 启动成功 (请手动停止，文件大小限制: 50.00 MB)';
        
        // 同时在右侧显示接口和文件大小信息
        if (data.interface) {
            interfaceInfoEl.style.display = 'inline-block';
            interfaceInfoEl.textContent = '接口: ' + data.interface;
        }
        if (fileExists) {
            fileSizeInfoEl.style.display = 'inline-block';
            fileSizeInfoEl.textContent = '文件大小: ' + formatFileSize(fileSize);
        }
        
        // 使用统一状态系统显示详细信息
        var statusMessage = 'TCPDump 启动成功';
        if (data.interface) {
            statusMessage += ' - 接口: ' + data.interface;
        }
        if (fileExists) {
            statusMessage += ' - 文件大小: ' + formatFileSize(fileSize);
        }
        statusMessage += ' - 请手动停止，文件大小限制: 50.00 MB';
        
        // 只在状态变化时显示通知
        if (window.lastStatus !== statusMessage) {
            showNotification(statusMessage, 'success');
            window.lastStatus = statusMessage;
        }

    } else {
        // 设置状态文本
        statusEl.className = 'cbi-value-description status-indicator-general';
        statusEl.textContent = '<%:已停止%>';
        
        // 使用统一状态系统显示详细信息
        var statusMessage = '<%:已停止%>';
        if (fileExists) {
            statusMessage += ' - 文件大小: ' + formatFileSize(fileSize);
        }
        
        // 只在状态变化时显示通知
        if (window.lastStatus !== statusMessage) {
            showNotification(statusMessage, 'info');
            window.lastStatus = statusMessage;
        }
    }
    
    if (startBtn) startBtn.disabled = isRunning;
    if (stopBtn) stopBtn.disabled = !isRunning;
    if (downloadBtn) downloadBtn.disabled = !fileExists || isRunning; 
    if (deleteBtn) deleteBtn.disabled = !fileExists || isRunning;
}

// ------------------------------------------------
// 操作函数 - 保持不变
// ------------------------------------------------
function startCapture() {
    var errors = validateInputs();
    if (errors.length > 0) {
        showNotification('<%:错误:%> ' + errors.join(', '), 'error');
        return;
    }
    
    var interface = document.getElementById('interface').value;
    var filter = document.getElementById('filter').value;
    var count = document.getElementById('count').value;
    
    var startBtn = document.getElementById('btn-start');
    if (startBtn) {
        startBtn.disabled = true;
        startBtn.textContent = '<%:启动中...%>';
    }
    
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '<%=url("admin/services/tcpdump/start")%>', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.timeout = 15000;
    
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.textContent = '<%:开始捕获%>';
            }
            setTimeout(updateStatus, 1000); 
            
            if (xhr.status === 200) {
                try {
                    var result = JSON.parse(xhr.responseText);
                    if (result.success) {
                        showNotification(result.message, 'success');
                    } else {
                        showNotification('<%:启动失败:%> ' + (result.message || '<%:未知错误%>'), 'error');
                    }
                } catch(e) {
                    showNotification('<%:响应解析失败%>', 'error');
                }
            } else {
               showNotification('<%:请求失败: HTTP %> ' + xhr.status, 'error');
            }
            updateStatus();
        }
    };
    
    xhr.ontimeout = function() {
        showNotification('<%:启动请求超时%>', 'error');
        if (startBtn) {
            startBtn.disabled = false;
            startBtn.textContent = '<%:开始捕获%>';
        }
    };
    
    var params = 'interface=' + encodeURIComponent(interface) + 
                 '&filter=' + encodeURIComponent(filter) + 
                 '&count=' + encodeURIComponent(count);
    xhr.send(params);
}


function stopCapture() {
    var stopBtn = document.getElementById('btn-stop');
    var originalText = stopBtn ? stopBtn.textContent : '';
    
    if (stopBtn) {
        stopBtn.disabled = true;
        stopBtn.textContent = '<%:停止中...%>';
    }
    
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '<%=url("admin/services/tcpdump/stop")%>', true);
    xhr.timeout = 15000;
    
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (stopBtn) {
                stopBtn.textContent = originalText;
            }
            
            if (xhr.status === 200) {
                try {
                    var result = JSON.parse(xhr.responseText);
                    if (result.success) {
                        showNotification(result.message, 'success');
                        updateStatus(); 
                        setTimeout(updateStatus, 2000);
                    } else {
                        showNotification('<%:停止失败:%> ' + (result.message || '<%:未知错误%>'), 'error');
                        updateStatus();
                    }
                } catch(e) {
                    showNotification('<%:响应解析失败%>', 'error');
                    updateStatus();
                }
            } else {
                showNotification('<%:停止请求失败，状态码:%> ' + xhr.status, 'error');
                updateStatus();
            }
        }
    };
    
    xhr.ontimeout = function() {
        showNotification('<%:停止请求超时，但进程可能仍在停止中%>', 'warning');
        if (stopBtn) {
            stopBtn.textContent = originalText;
        }
        updateStatus();
    };
    
    xhr.send();
}

function downloadCapture() {
    var downloadBtn = document.getElementById('btn-download');
    if (downloadBtn) downloadBtn.disabled = true;

    window.open('<%=url("admin/services/tcpdump/download")%>', '_blank');
    
    setTimeout(function() {
        updateStatus(); 
    }, 2000); 
}

function deleteCapture() {
    // 检查是否已经显示了确认通知
    if (window.deleteConfirmationVisible) {
        // 如果已经显示了确认通知，则执行删除操作
        window.deleteConfirmationVisible = false;
        proceedWithDelete();
        return;
    }
    
    // 显示删除确认通知
    showNotification('<%:您确定要删除 /tmp/tcpdump.pcap 文件吗？此操作无法撤销。%>\n\n<button id="confirm-delete" class="cbi-button cbi-button-negative">确认删除</button>', 'warning');
    
    // 标记确认通知可见
    window.deleteConfirmationVisible = true;
    
    // 为确认按钮添加事件监听器
    setTimeout(function() {
        var confirmBtn = document.getElementById('confirm-delete');
        if (confirmBtn) {
            confirmBtn.onclick = function() {
                window.deleteConfirmationVisible = false;
                proceedWithDelete();
            };
        }
    }, 100);
}

// 执行删除操作的函数
function proceedWithDelete() {
    var deleteBtn = document.getElementById('btn-delete');
    if (deleteBtn) {
        deleteBtn.disabled = true;
        deleteBtn.textContent = '<%:删除中...%>';
    }

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '<%=url("admin/services/tcpdump/delete")%>', true);
    
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            if (deleteBtn) {
                deleteBtn.disabled = false;
                deleteBtn.textContent = '<%:删除文件%>';
            }
            setTimeout(updateStatus, 500);
            
            if (xhr.status === 200) {
                try {
                    var result = JSON.parse(xhr.responseText);
                    if (result.success) {
                        showNotification(result.message, 'success');
                    } else {
                        showNotification(result.message || '<%:删除失败%>', 'error');
                    }
                } catch(e) {
                    showNotification('<%:删除响应解析失败%>', 'error');
                }
            } else {
                showNotification('<%:删除请求失败:%> ' + xhr.status, 'error');
            }
        }
    };
    
    xhr.send();
}

function refreshInterfaces() {
    var refreshBtn = document.getElementById('btn-refresh');
    var originalText = refreshBtn ? refreshBtn.textContent : '';

    if (refreshBtn) {
        refreshBtn.disabled = true;
        refreshBtn.textContent = '<%:刷新中...%>';
    }
    
    loadInterfaces();
    
    setTimeout(function() {
        if (refreshBtn) {
            refreshBtn.disabled = false;
            refreshBtn.textContent = originalText;
        }
        updateStatus();
    }, 1500); 
}

// ------------------------------------------------
// 初始化
// ------------------------------------------------
document.addEventListener('DOMContentLoaded', function() {
    setupPortSelector();
    loadInterfaces();
    updateStatus();
    
    var countInput = document.getElementById('count');
    if (countInput) {
        countInput.addEventListener('change', function() {
            var value = parseInt(this.value);
            if (isNaN(value) || value < 1) this.value = '';
            else if (value > 100000) this.value = 100000;
        });
    }
    
    setInterval(updateStatus, tcpdumpState.updateInterval);
    
    document.addEventListener('visibilitychange', function() {
        if (!document.hidden) {
            updateStatus();
        }
    });
    
    document.addEventListener('keydown', function(e) {
        if (e.ctrlKey || e.metaKey) {
            switch(e.key) {
                case 'Enter':
                    e.preventDefault();
                    document.getElementById('btn-start').click(); 
                    break;
                case 'Escape':
                    e.preventDefault();
                    document.getElementById('btn-stop').click();
                    break;
            }
        }
    });
});

//]]>
</script>

<%+footer%>
