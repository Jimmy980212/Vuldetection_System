const pages = {
  overview: {
    title: "概览仪表盘",
    subtitle: "聚合多Agent检测流水线、关键风险、代码证据与报告摘要",
    eyebrow: "Security Operations",
  },
  projects: {
    title: "项目管理",
    subtitle: "管理和维护检测项目，支持多项目并行检测与分析",
    eyebrow: "Project Hub",
  },
  analysis: {
    title: "代码分析",
    subtitle: "基于静态分析和多维特征提取，对代码进行深度分析与可视化",
    eyebrow: "Code Intelligence",
  },
  tasks: {
    title: "检测任务",
    subtitle: "管理和监控所有检测任务的执行状态、调度与资源消耗",
    eyebrow: "Detection Jobs",
  },
  results: {
    title: "漏洞结果",
    subtitle: "展示检测到的所有漏洞，支持多维度筛选、统计与管理",
    eyebrow: "Vulnerability Findings",
  },
  agents: {
    title: "Agent监控",
    subtitle: "实时监控多Agent运行状态、性能指标与资源消耗",
    eyebrow: "Agent Runtime",
  },
  settings: {
    title: "系统配置",
    subtitle: "配置和管理 LLM 模型、API 服务与全局推理参数",
    eyebrow: "Model Ops",
  },
  reports: {
    title: "报告管理",
    subtitle: "管理和查看漏洞检测报告，支持导出、分享和历史版本对比",
    eyebrow: "Reports",
  },
  docs: {
    title: "帮助文档",
    subtitle: "快速了解 VulSage 智擎的基本使用流程",
    eyebrow: "Documentation",
  },
};

const stats = [
  ["代码规模", "18.7M", "总代码行数", "file-text", ""],
  ["检测任务", "24", "完成任务数", "clipboard-check", "green"],
  ["发现漏洞", "37", "高危漏洞 12 个", "shield-alert", "red"],
  ["平均检测耗时", "8m 42s", "较上次 ↓ 23%", "clock-3", ""],
  ["Token节省率", "86.3%", "累计节省 3.42M", "chart-pie", "purple"],
];

const pipeline = [
  ["预处理Agent", "代码解析与过滤", "scan-search", "29,124,255"],
  ["切片Agent", "程序切片与靶点", "slice", "17,217,197"],
  ["建模Agent", "CPG构建与特征提取", "network", "24,201,141"],
  ["推理Agent", "LLM漏洞推理", "brain-circuit", "255,159,26"],
  ["验证Agent", "结果验证与过滤", "shield-check", "138,92,255"],
  ["报告Agent", "报告生成与输出", "file-chart-column", "90,167,255"],
];

const vulns = [
  ["高危", "越界访问 (CWE-787)", "fs/buffer.c:1024", "memset组件可能导致目标缓冲区越界访问", "high"],
  ["中危", "空指针解引用 (CWE-476)", "mm/page_alloc.c:512", "可能存在空指针解引用风险", "mid"],
  ["中危", "释放后引用 (CWE-416)", "drivers/net/net.c:2057", "释放内存后未置空，存在使用风险", "mid"],
  ["低危", "缓冲区溢出 (CWE-120)", "lib/string.c:87", "strcpy可能导致缓冲区溢出", "low"],
];

const projects = [
  ["Linux Kernel 6.6.0", "Linux 内核 6.6.0 版本源码安全检测与漏洞分析", "C", "8.7M", "高 12", "中 15", "低 8", "进行中"],
  ["FFmpeg 6.1", "多媒体处理框架 FFmpeg 6.1 漏洞检测项目", "C/C++", "2.1M", "高 8", "中 11", "低 6", "已完成"],
  ["QEMU 8.2.0", "开源虚拟机 QEMU 8.2.0 安全分析项目", "C", "1.9M", "高 5", "中 7", "低 4", "已完成"],
  ["Chromium 121.0", "Chromium 浏览器内核安全检测", "C++", "3.2M", "高 15", "中 20", "低 12", "未开始"],
  ["Redis 7.2.4", "高性能键值数据库 Redis 安全检测", "C", "0.5M", "高 2", "中 3", "低 1", "未开始"],
  ["OpenSSL 3.2.0", "SSL/TLS 加密库 OpenSSL 安全分析", "C", "1.3M", "高 7", "中 9", "低 5", "已暂停"],
  ["SQLite 3.45.0", "轻量级数据库 SQLite 安全检测项目", "C", "0.3M", "高 1", "中 2", "低 1", "已完成"],
  ["cURL 8.6.0", "命令行数据传输工具 cURL 安全检测", "C", "0.2M", "高 0", "中 1", "低 1", "已完成"],
];

const tasks = [
  ["TASK-20250601-001", "Linux内核定时扫描", "Linux Kernel 6.6.0", "drivers/", "4/6 推理Agent", "运行中", 65, "12m 34s", "234.5K"],
  ["TASK-20250601-002", "网络模块风险检测", "Linux Kernel 6.6.0", "net/", "3/6 建模Agent", "运行中", 42, "7m 18s", "128.7K"],
  ["TASK-20250531-001", "FFmpeg 媒体处理检测", "FFmpeg 6.1", "libavcodec/", "6/6 报告Agent", "已完成", 100, "18m 45s", "412.3K"],
  ["TASK-20250531-002", "QEMU 虚拟化检测", "QEMU 8.2.0", "hw/", "6/6 报告Agent", "已完成", 100, "22m 16s", "523.1K"],
  ["TASK-20250530-001", "Linux 内存管理检测", "Linux Kernel 6.6.0", "mm/", "6/6 验证Agent", "已失败", 100, "9m 32s", "186.4K"],
  ["TASK-20250530-002", "驱动模块安全检测", "Linux Kernel 6.6.0", "drivers/staging/", "1/6 预处理Agent", "等待中", 0, "-", "-"],
];

const findings = [
  ["VUL-2025-0001", "高危", "越界访问 (CWE-787)", "fs/buffer.c", 1024, "copy_from_user", "静态分析", "已确认", "92.7%"],
  ["VUL-2025-0002", "高危", "空指针解引用 (CWE-476)", "mm/page_alloc.c", 512, "__alloc_pages", "LLM推理", "已确认", "89.3%"],
  ["VUL-2025-0003", "高危", "释放后引用 (CWE-416)", "drivers/net/net.c", 2057, "netif_rx", "静态分析", "待确认", "78.6%"],
  ["VUL-2025-0004", "中危", "缓冲区溢出 (CWE-120)", "lib/string.c", 87, "strcpy", "静态分析", "已确认", "65.4%"],
  ["VUL-2025-0005", "中危", "越界访问 (CWE-787)", "arch/x86/entry.c", 642, "entry_SYSCALL_64", "LLM推理", "已确认", "91.1%"],
  ["VUL-2025-0006", "中危", "未初始化变量 (CWE-457)", "kernel/sched/core.c", 3421, "schedule", "静态分析", "待确认", "60.2%"],
  ["VUL-2025-0007", "低危", "整数溢出 (CWE-190)", "crypto/hash.c", 128, "hash_update", "静态分析", "已确认", "55.3%"],
  ["VUL-2025-0008", "低危", "竞争条件 (CWE-362)", "fs/ext4/inode.c", 2210, "ext4_iget", "LLM推理", "误报", "34.6%"],
];

const agents = [
  ["预处理Agent", "运行中", "TASK-2025-00024", 68, "18s", "120.4K", "28%", "512MB", "98.6%"],
  ["切片Agent", "运行中", "TASK-2025-00024", 56, "21s", "210.7K", "32%", "768MB", "96.1%"],
  ["建模Agent", "运行中", "TASK-2025-00024", 72, "35s", "334.2K", "45%", "1.02GB", "95.3%"],
  ["推理Agent (LLM)", "运行中", "TASK-2025-00024", 83, "1m 28s", "1.45M", "65%", "2.45GB", "92.8%"],
  ["验证Agent", "运行中", "TASK-2025-00024", 64, "32s", "456.3K", "38%", "896MB", "94.7%"],
  ["报告Agent", "运行中", "TASK-2025-00024", 90, "15s", "78.9K", "22%", "512MB", "97.2%"],
  ["总控Agent", "排队中", "--", 0, "--", "--", "0%", "256MB", "--"],
];

const models = [
  ["DeepSeek-R1", "推理模型", "DeepSeek", "R1-32B", "启用", "128K", "4K", "0.2"],
  ["Qwen2.5-72B-Instruct", "对话模型", "阿里云通义", "2.5-72B", "启用", "128K", "4K", "0.3"],
  ["GPT-4o", "对话模型", "OpenAI", "GPT-4o", "启用", "128K", "4K", "0.3"],
  ["Claude-3.5-Sonnet", "对话模型", "Anthropic", "3.5-Sonnet", "禁用", "200K", "4K", "0.3"],
  ["Mixtral-8x22B", "对话模型", "Mistral AI", "8x22B", "禁用", "64K", "4K", "0.3"],
];

const reports = [
  ["Linux Kernel 6.6.0 漏洞检测报告", "RPT-20250601-001", "Linux Kernel 6.6.0", "完整报告", 128, 236, 482, 846, "2025-06-01 14:32:45", "已完成"],
  ["FFmpeg 6.1 漏洞检测报告", "RPT-20250531-002", "FFmpeg 6.1", "完整报告", 96, 178, 321, 595, "2025-05-31 18:20:11", "已完成"],
  ["QEMU 8.2.0 漏洞检测报告", "RPT-20250531-003", "QEMU 8.2.0", "完整报告", 74, 143, 298, 515, "2025-05-31 11:05:33", "已完成"],
  ["Linux Kernel 6.5.0 对比分析报告", "RPT-20250530-004", "Linux Kernel 6.6.0 vs 6.5.0", "对比报告", 42, 89, 156, 287, "2025-05-30 16:45:20", "已完成"],
  ["Chromium 121.0 漏洞检测报告", "RPT-20250529-005", "Chromium 121.0", "完整报告", 63, 112, 201, 376, "2025-05-29 19:18:07", "已完成"],
  ["自定义项目快速扫描报告", "RPT-20250528-006", "Custom Project", "快速报告", 15, 32, 61, 108, "2025-05-28 10:22:31", "已完成"],
];

const app = document.querySelector("#app");

function icon(name, cls = "") {
  return `<i data-lucide="${name}"${cls ? ` class="${cls}"` : ""}></i>`;
}

function refreshIcons() {
  if (window.lucide) {
    window.lucide.createIcons({
      attrs: { "stroke-width": 1.7 },
    });
  }
}

function pageHead(key, actions = "") {
  const p = pages[key];
  return `
    <section class="page-head">
      <div>
        <span class="eyebrow">${p.eyebrow}</span>
        <h1>${p.title}</h1>
        <p class="page-subtitle">${p.subtitle}</p>
      </div>
      <div class="head-actions">${actions}</div>
    </section>
  `;
}

function statCards(items = stats) {
  return `<section class="cards-grid">${items
    .map(
      ([label, value, note, iconName, tone]) => `
        <article class="stat-card">
          <div>
            <span>${label}</span>
            <strong>${value}</strong>
            <small>${note.includes("↓") || note.includes("↑") ? `<em class="delta">${note}</em>` : note}</small>
          </div>
          <div class="stat-icon ${tone}">${icon(iconName)}</div>
        </article>
      `,
    )
    .join("")}</section>`;
}

function pipelineView() {
  return `
    <section class="panel">
      <div class="panel-title">
        <div>
          <h2>检测流程 (Multi-Agent Pipeline)</h2>
        </div>
        <button class="small-btn">${icon("arrow-right")}查看详情</button>
      </div>
      <div class="pipeline">
        ${pipeline
          .map(
            ([name, desc, iconName, rgb], i) => `
          <article class="flow-card" style="--flow-rgb:${rgb}">
            <div class="step">${icon(iconName)}</div>
            <b>${i + 1} ${name}</b>
            <small>${desc}</small>
          </article>`,
          )
          .join("")}
      </div>
    </section>
  `;
}

function codePanel() {
  const rows = [
    ["1018", '<span class="kw">int</span> <span class="fn">copy_from_user</span>(<span class="type">void</span> *to, <span class="type">const void</span> __user *from, <span class="type">unsigned long</span> n)', ""],
    ["1019", "{", ""],
    ["1020", '<span class="kw">if</span> (access_ok(VERIFY_READ, from, n)) {', ""],
    ["1021", '<span class="type">unsigned long</span> not_copied;', ""],
    ["1022", "not_copied = raw_copy_from_user(to, from, n);", ""],
    ["1023", '<span class="kw">if</span> (!not_copied)', ""],
    ["1024", '<span class="kw">return</span> <span class="num">0</span>;', "触发访问"],
    ["1025", "memset(to + (n - not_copied), 0, not_copied);", ""],
    ["1026", '<span class="kw">return</span> -EFAULT;', ""],
    ["1027", "}", ""],
    ["1028", '<span class="kw">return</span> -EFAULT;', ""],
    ["1029", "}", ""],
  ];
  return `
    <section class="panel code-panel">
      <div class="panel-title">
        <div>
          <h2>可疑代码片段</h2>
          <p>fs/buffer.c:1024</p>
        </div>
        <div class="code-toolbar">
          <span class="toggle">高亮显示 <span class="switch"></span></span>
        </div>
      </div>
      <div class="code-window" aria-label="代码片段">
        ${rows
          .map(
            ([ln, code, tag]) => `
          <div class="code-line ${tag ? "is-hot" : ""}">
            <span class="ln">${ln}</span>
            <span>${code}</span>
            ${tag ? `<span class="code-tag">${tag}</span>` : "<span></span>"}
          </div>`,
          )
          .join("")}
      </div>
      <div class="summary-box">
        <b>上下文摘要</b><br />
        函数 copy_from_user 将用户空间数据拷贝到内核空间。当 not_copied &gt; 0 时，memset 操作可能会对目标缓冲区进行越界写入，存在越界访问风险。
      </div>
    </section>
  `;
}

function graphPanel() {
  return `
    <section class="panel">
      <div class="panel-title">
        <div>
          <h2>代码属性图 (CPG) 可视化</h2>
          <p>函数、调用、条件与数据流关系</p>
        </div>
        <button class="icon-btn" aria-label="适配视图">${icon("scan")}</button>
      </div>
      <div class="graph">
        <svg viewBox="0 0 520 340" role="img" aria-label="CPG可视化图">
          <defs>
            <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
              <path d="M0,0 L0,6 L8,3 z" fill="rgba(17,217,197,.72)"></path>
            </marker>
            <marker id="arrowRed" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
              <path d="M0,0 L0,6 L8,3 z" fill="rgba(255,70,77,.72)"></path>
            </marker>
          </defs>
          <path class="edge" marker-end="url(#arrow)" d="M260 54 L150 112"></path>
          <path class="edge" marker-end="url(#arrow)" d="M260 54 L368 112"></path>
          <path class="edge" marker-end="url(#arrow)" d="M150 142 C150 176 214 178 240 196"></path>
          <path class="edge" marker-end="url(#arrow)" d="M368 142 C368 184 310 181 280 197"></path>
          <path class="edge" marker-end="url(#arrow)" d="M260 222 L180 274"></path>
          <path class="edge" marker-end="url(#arrow)" d="M260 222 L330 274"></path>
          <path class="edge edge-hot" marker-end="url(#arrowRed)" d="M368 142 C430 182 414 250 350 284"></path>

          <rect class="node" x="190" y="28" width="140" height="38" rx="6"></rect>
          <text x="260" y="52" fill="#f4f8ff" text-anchor="middle" font-size="13">copy_from_user</text>
          <rect class="node" x="82" y="112" width="136" height="38" rx="6"></rect>
          <text x="150" y="136" fill="#f4f8ff" text-anchor="middle" font-size="13">access_ok</text>
          <rect class="node" x="306" y="112" width="126" height="38" rx="6"></rect>
          <text x="369" y="136" fill="#f4f8ff" text-anchor="middle" font-size="13">raw_copy</text>
          <rect class="node node-ok" x="204" y="196" width="112" height="42" rx="18"></rect>
          <text x="260" y="222" fill="#dffef8" text-anchor="middle" font-size="13">!not_copied</text>
          <rect class="node" x="128" y="274" width="106" height="38" rx="6"></rect>
          <text x="181" y="298" fill="#f4f8ff" text-anchor="middle" font-size="13">return 0</text>
          <rect class="node node-hot" x="300" y="274" width="104" height="38" rx="6"></rect>
          <text x="352" y="298" fill="#ffe8ea" text-anchor="middle" font-size="13">memset</text>
        </svg>
      </div>
    </section>
  `;
}

function donutPanel(title, alt = false) {
  const legend = alt
    ? [
        ["推理Agent (LLM)", "1.45M (42.4%)", "red"],
        ["建模Agent", "334.2K (9.8%)", "orange"],
        ["验证Agent", "456.3K (13.3%)", "yellow"],
        ["切片Agent", "210.7K (6.2%)", "green"],
        ["其他", "768.5K (22.5%)", "purple"],
      ]
    : [
        ["高危 (12)", "32.4%", "red"],
        ["中危 (15)", "40.5%", "orange"],
        ["低危 (8)", "21.6%", "yellow"],
        ["提示 (2)", "5.4%", ""],
      ];
  return `
    <section class="panel">
      <div class="panel-title">
        <h2>${title}</h2>
        ${!alt ? '<div class="tabs"><button class="chip-btn is-active">按严重程度</button><button class="chip-btn">按漏洞类型</button></div>' : ""}
      </div>
      <div class="donut-wrap">
        <div class="donut ${alt ? "alt" : ""}" data-label="${alt ? "3.42M&#10;总计" : "37&#10;总计"}"></div>
        <div class="legend">
          ${legend
            .map(
              ([name, value, tone]) => `
            <div class="legend-row">
              <span class="swatch ${tone}"></span><span>${name}</span><b>${value}</b>
            </div>`,
            )
            .join("")}
        </div>
      </div>
    </section>
  `;
}

function vulnListPanel() {
  return `
    <section class="panel">
      <div class="panel-title">
        <h2>漏洞列表</h2>
        <button class="small-btn">全部类型 ${icon("chevron-down")}</button>
      </div>
      <div class="vuln-list">
        ${vulns
          .map(
            ([sev, title, loc, desc, tone]) => `
          <article class="vuln-item ${tone}">
            <span class="badge ${tone}">${sev}</span>
            <div><b>${title}</b><small>${loc}<br />${desc}</small></div>
            <button class="small-btn">详情</button>
          </article>`,
          )
          .join("")}
      </div>
      <div class="table-footer"><span></span><a class="link" href="#" data-page="results">查看全部 (37)</a></div>
    </section>
  `;
}

function insightPanel() {
  return `
    <section class="panel">
      <div class="panel-title">
        <h2>LLM推理结论</h2>
      </div>
      <div class="insight">
        <div class="score-medal">${icon("shield-check")}</div>
        <p><b>漏洞判定：越界访问 (CWE-787)</b>，置信度 92.7%。当 not_copied &gt; 0 时，表达式 (n - not_copied) 可能大于目标缓冲区剩余空间，导致 memset 对缓冲区越界写入。</p>
      </div>
    </section>
  `;
}

function lineChart() {
  return `
    <div class="line-chart">
      <svg viewBox="0 0 680 230" role="img" aria-label="趋势图">
        <defs>
          <linearGradient id="areaBlue" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stop-color="#1d7cff" stop-opacity=".28"></stop>
            <stop offset="1" stop-color="#1d7cff" stop-opacity="0"></stop>
          </linearGradient>
        </defs>
        ${[40, 80, 120, 160, 200].map((y) => `<line class="chart-grid" x1="42" y1="${y}" x2="650" y2="${y}"></line>`).join("")}
        <path class="chart-area" d="M42 176 L80 150 L118 122 L156 132 L194 106 L232 110 L270 88 L308 98 L346 76 L384 86 L422 62 L460 72 L498 50 L536 64 L574 42 L612 54 L650 32 L650 204 L42 204 Z"></path>
        <polyline class="chart-line-blue" points="42,176 80,150 118,122 156,132 194,106 232,110 270,88 308,98 346,76 384,86 422,62 460,72 498,50 536,64 574,42 612,54 650,32"></polyline>
        <polyline class="chart-line-orange" points="42,188 80,176 118,164 156,168 194,151 232,148 270,132 308,142 346,124 384,126 422,108 460,118 498,98 536,106 574,86 612,98 650,78"></polyline>
        <polyline class="chart-line-cyan" points="42,204 80,198 118,192 156,190 194,184 232,180 270,176 308,174 346,166 384,170 422,158 460,160 498,152 536,154 574,142 612,148 650,138"></polyline>
        <text class="chart-label" x="42" y="224">05-17</text>
        <text class="chart-label" x="184" y="224">05-21</text>
        <text class="chart-label" x="326" y="224">05-25</text>
        <text class="chart-label" x="468" y="224">05-29</text>
        <text class="chart-label" x="610" y="224">06-01</text>
      </svg>
    </div>
  `;
}

function barChart() {
  const heights = [58, 86, 112, 142, 104, 72, 44];
  return `
    <div class="bar-chart">
      <svg viewBox="0 0 540 230" role="img" aria-label="柱状图">
        <defs>
          <linearGradient id="barBlue" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0" stop-color="#1d7cff"></stop>
            <stop offset="1" stop-color="#0e3fbd"></stop>
          </linearGradient>
        </defs>
        ${[50, 90, 130, 170, 210].map((y) => `<line class="chart-grid" x1="32" y1="${y}" x2="512" y2="${y}"></line>`).join("")}
        ${heights.map((h, i) => `<rect class="bar" x="${54 + i * 66}" y="${204 - h}" width="28" height="${h}" rx="4"></rect>`).join("")}
        ${["0-1s", "1-5s", "5-10s", "10-30s", "30s-1m", "1-2m", ">5m"].map((x, i) => `<text class="chart-label" x="${48 + i * 66}" y="224">${x}</text>`).join("")}
      </svg>
    </div>
  `;
}

function tableShell(headers, rows, footer = "共 128 条") {
  return `
    <section class="panel">
      <div class="table-shell">
        <table class="data-table">
          <thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="table-footer">
        <span>${footer}</span>
        <div class="pager">
          <button>${icon("chevron-left")}</button><button class="is-active">1</button><button>2</button><button>3</button><button>${icon("chevron-right")}</button>
        </div>
      </div>
    </section>
  `;
}

function searchRow(button = "") {
  return `
    <section class="search-row">
      <label class="search-box">${icon("search")}<input placeholder="搜索项目、任务、文件、CWE..." /></label>
      <button class="select-box">全部项目 ${icon("chevron-down")}</button>
      <button class="select-box">全部状态 ${icon("chevron-down")}</button>
      <button class="select-box">最近更新 ${icon("chevron-down")}</button>
      ${button || `<button class="ghost-btn">${icon("rotate-cw")}重置</button>`}
    </section>
  `;
}

function renderOverview() {
  app.innerHTML = `
    ${pageHead("overview", `<button class="ghost-btn">${icon("download")}导出摘要</button><button class="primary-action">${icon("plus")}新建检测</button>`)}
    ${statCards()}
    ${pipelineView()}
    <section class="work-grid">
      <div>
        ${codePanel()}
        ${graphPanel()}
        ${insightPanel()}
      </div>
      <aside class="right-stack">
        ${donutPanel("漏洞分布统计")}
        ${vulnListPanel()}
        <section class="panel">
          <div class="panel-title"><h2>报告摘要</h2></div>
          <p class="page-subtitle">本次检测共发现 37 个漏洞，其中高危 12 个、中危 15 个、低危 8 个、提示 2 个。报告已生成，可下载完整结果。</p>
          <div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap">
            <button class="primary-action">${icon("download")}下载报告</button>
            <button class="ghost-btn">${icon("share-2")}分享报告</button>
          </div>
        </section>
      </aside>
    </section>
  `;
}

function renderProjects() {
  const rows = projects
    .map(
      (p) => `
        <tr>
          <td><b>${p[0]}</b></td><td>${p[1]}</td><td><span class="badge info">${p[2]}</span></td><td>${p[3]}</td>
          <td><span style="color:var(--red)">${p[4]}</span> <span style="color:var(--orange)">${p[5]}</span> <span style="color:var(--green)">${p[6]}</span></td>
          <td><span class="badge ${p[7] === "已完成" ? "ok" : "info"}">${p[7]}</span></td><td>2025-06-01 14:32:45</td>
          <td><button class="table-action" aria-label="运行">${icon("play")}</button><button class="table-action" aria-label="图表">${icon("bar-chart-3")}</button><button class="table-action" aria-label="更多">${icon("ellipsis")}</button></td>
        </tr>`,
    )
    .join("");
  app.innerHTML = `
    ${pageHead("projects", `<button class="primary-action">${icon("plus")}新建项目</button>`)}
    ${statCards([
      ["项目总数", "8", "个项目", "folder", ""],
      ["活跃项目", "3", "个项目", "activity", "green"],
      ["已完成项目", "5", "个项目", "circle-check", "purple"],
      ["总代码行数", "18.7M", "行", "code-2", "orange"],
      ["漏洞总数", "128", "个", "shield-alert", "red"],
    ])}
    ${searchRow(`<button class="primary-action">${icon("plus")}新建项目</button>`)}
    ${tableShell(["项目名称", "项目描述", "语言", "代码行数", "漏洞数", "状态", "最后检测时间", "操作"], rows, "共 8 条")}
  `;
}

function renderAnalysis() {
  app.innerHTML = `
    ${pageHead("analysis", `<button class="ghost-btn">${icon("refresh-cw")}重新分析</button><button class="ghost-btn">${icon("download")}导出分析结果</button>`)}
    ${statCards([
      ["文件路径", "fs/buffer.c:1024", "当前分析目标", "file-code-2", ""],
      ["文件大小", "45.2KB", "源代码文件", "hard-drive", "green"],
      ["代码行数", "2,854", "函数数量 28", "list-tree", ""],
      ["复杂度", "15", "高复杂度", "activity", "orange"],
      ["分析状态", "完成", "2025-06-01 14:32:45", "circle-check", "green"],
    ])}
    <section class="panel">
      <div class="tabs">
        ${["代码视图", "函数视图", "CFG控制流图", "DFG数据流图", "CPG属性图", "依赖关系", "切片视图"].map((x, i) => `<button class="chip-btn ${i === 0 ? "is-active" : ""}">${x}</button>`).join("")}
      </div>
    </section>
    <section class="work-grid">
      <div>
        ${codePanel()}
        <section class="panel">
          <div class="panel-title"><h2>相关函数调用链</h2></div>
          <div class="pipeline" style="grid-template-columns:repeat(5,minmax(120px,1fr))">
            ${["sys_read", "vfs_read", "new_sync_read", "copy_from_user", "raw_copy_from_user"].map((x, i) => `<article class="flow-card" style="--flow-rgb:${i === 3 ? "255,70,77" : "29,124,255"}"><b>${x}</b><small>fs/read_write.c:${642 + i * 184}</small></article>`).join("")}
          </div>
        </section>
        ${insightPanel()}
      </div>
      <aside class="right-stack">
        <section class="panel">
          <div class="panel-title"><h2>代码属性信息</h2></div>
          <div class="legend">
            ${[["函数名", "copy_from_user"], ["所属文件", "fs/buffer.c"], ["起始行号", "1018"], ["结束行号", "1030"], ["函数长度", "13 行"], ["返回类型", "int"], ["圈复杂度", "15 (高)"], ["调用次数", "156 次"]].map(([a, b]) => `<div class="legend-row"><span></span><span>${a}</span><b>${b}</b></div>`).join("")}
          </div>
        </section>
        <section class="panel">
          <div class="panel-title"><h2>风险评分</h2></div>
          <div class="donut-wrap" style="grid-template-columns:120px 1fr">
            <div class="donut" data-label="9.2/10"></div>
            <div class="legend">
              ${["可利用性 9.1", "影响范围 9.3", "复杂度 7.8", "检测难度 8.5"].map((x) => `<div class="legend-row"><span class="swatch red"></span><span>${x}</span><b>高</b></div>`).join("")}
            </div>
          </div>
        </section>
        ${vulnListPanel()}
      </aside>
    </section>
  `;
}

function renderTasks() {
  const rows = tasks
    .map(
      (t) => `
        <tr>
          <td><b>${t[0]}</b><br><span style="color:var(--muted)">${t[1]}</span></td><td>${t[2]}</td><td>${t[3]}</td><td>多Agent协同</td>
          <td><span class="badge ${t[5] === "已失败" ? "high" : t[5] === "已完成" ? "ok" : "info"}">${t[5]}</span><div class="progress-cell"><div class="progress ${t[5] === "已失败" ? "red" : ""}"><span style="width:${t[6]}%"></span></div><span>${t[6]}%</span></div></td>
          <td>${t[4]}</td><td>${t[7]}</td><td>${t[8]}</td><td><button class="table-action">${icon(t[5] === "运行中" ? "pause" : "play")}</button><button class="table-action">${icon("ellipsis")}</button></td>
        </tr>`,
    )
    .join("");
  app.innerHTML = `
    ${pageHead("tasks", `<button class="primary-action">${icon("plus")}新建检测任务</button>`)}
    ${statCards([
      ["任务总数", "24", "个任务", "layers-3", ""],
      ["运行中", "6", "个任务", "play", "green"],
      ["已完成", "15", "个任务", "circle-check", "purple"],
      ["失败任务", "2", "个任务", "x", "red"],
      ["平均耗时", "8m 42s", "较上次 ↓ 23%", "clock-3", ""],
    ])}
    ${searchRow(`<button class="primary-action">${icon("plus")}新建检测任务</button>`)}
    ${tableShell(["任务信息", "所属项目", "扫描范围", "Agent策略", "状态 / 进度", "任务阶段", "耗时", "Token消耗", "操作"], rows, "共 24 条")}
    <section class="work-grid">
      <section class="panel"><div class="panel-title"><h2>任务执行趋势</h2></div>${lineChart()}</section>
      <section class="panel"><div class="panel-title"><h2>阶段耗时占比</h2></div>${donutPanel("阶段耗时占比", true)}</section>
    </section>
  `;
}

function renderResults() {
  const rows = findings
    .map(
      (f) => `
      <tr>
        <td><input type="checkbox" /></td><td>${f[0]}</td><td><span class="badge ${f[1] === "高危" ? "high" : f[1] === "中危" ? "mid" : "low"}">${f[1]}</span></td><td>${f[2]}</td><td>${f[3]}</td><td>${f[4]}</td><td>${f[5]}</td><td><span class="badge info">${f[6]}</span></td><td><span class="badge ${f[7] === "已确认" ? "ok" : f[7] === "误报" ? "high" : "mid"}">${f[7]}</span></td><td>${f[8]}</td><td><button class="table-action">${icon("eye")}</button><button class="table-action">${icon("git-branch")}</button></td>
      </tr>`,
    )
    .join("");
  app.innerHTML = `
    ${pageHead("results", `<button class="ghost-btn">${icon("download")}导出CSV</button><button class="primary-action">${icon("file-down")}生成报告</button>`)}
    ${statCards([
      ["漏洞总数", "128", "较上次 ↑ 18.2%", "shield-alert", "red"],
      ["高危漏洞", "12", "较上次 ↑ 9.1%", "triangle-alert", "red"],
      ["中危漏洞", "15", "较上次 ↓ 6.3%", "badge-alert", "orange"],
      ["低危漏洞", "8", "较上次 ↓ 20.0%", "shield", "green"],
      ["已确认漏洞", "37", "占比 28.9%", "badge-check", "green"],
    ])}
    ${searchRow()}
    <section class="dashboard-grid">
      <div>${tableShell(["", "漏洞ID", "风险等级", "漏洞类型 (CWE)", "文件路径", "行号", "函数名", "检测来源", "状态", "置信度", "操作"], rows)}</div>
      <aside class="right-stack">
        <section class="panel"><div class="panel-title"><h2>漏洞趋势 (近30天)</h2></div>${lineChart()}</section>
        ${donutPanel("漏洞类型分布 (CWE Top 5)")}
        ${donutPanel("检测来源分布", true)}
      </aside>
    </section>
  `;
}

function renderAgents() {
  const rows = agents
    .map(
      (a) => `
      <tr><td>${a[0]}</td><td><span class="badge ${a[1] === "运行中" ? "ok" : "info"}">${a[1]}</span></td><td>${a[2]}</td><td><div class="progress-cell"><div class="progress"><span style="width:${a[3]}%"></span></div><span>${a[3]}%</span></div></td><td>${a[4]}</td><td>${a[5]}</td><td>${a[6]}</td><td>${a[7]}</td><td>${a[8]}</td><td><button class="table-action">${icon("bar-chart-3")}</button><button class="table-action">${icon("eye")}</button></td></tr>`,
    )
    .join("");
  app.innerHTML = `
    ${pageHead("agents", `<button class="ghost-btn">${icon("refresh-cw")}刷新</button><button class="ghost-btn">${icon("maximize")}全屏监控</button>`)}
    ${statCards([
      ["Agent总数", "7", "在线 7 · 离线 0", "bot", ""],
      ["总任务数", "24", "较上次 ↑ 20.0%", "list-checks", "green"],
      ["平均执行耗时", "2m 41s", "较上次 ↓ 12.3%", "clock-3", ""],
      ["总Token消耗", "3.42M", "较上次 ↑ 18.6%", "sparkles", "purple"],
      ["成功率", "94.2%", "较上次 ↑ 6.4%", "trending-up", "green"],
    ])}
    <section class="panel">
      <div class="panel-title"><h2>多Agent执行流程 (实时)</h2><p>自动刷新 5s</p></div>
      <div class="agent-flow">${agents.map((a, i) => `<article class="agent-step"><span class="step">${icon(pipeline[i % pipeline.length][2])}</span><b>${a[0]}</b><small>${a[1]} · 耗时 ${a[4]}</small><div class="meter green"><span style="width:${a[3]}%"></span></div></article>`).join("")}</div>
    </section>
    <section class="dashboard-grid">
      <div>${tableShell(["Agent名称", "状态", "当前任务", "进度", "平均耗时", "Token消耗", "CPU使用率", "内存使用率", "成功率", "操作"], rows, "共 7 个 Agent")}</div>
      <aside class="right-stack">
        <section class="panel"><div class="panel-title"><h2>实时资源消耗趋势</h2></div>${lineChart()}</section>
        ${donutPanel("Token消耗分布", true)}
      </aside>
    </section>
  `;
}

function renderSettings() {
  const rows = models
    .map(
      (m) => `<tr><td><b>${m[0]}</b></td><td>${m[1]}</td><td>${m[2]}</td><td>${m[3]}</td><td><span class="badge ${m[4] === "启用" ? "ok" : "info"}">${m[4]}</span></td><td>${m[5]}</td><td>${m[6]}</td><td>${m[7]}</td><td><button class="table-action">${icon("pencil")}</button><button class="table-action">${icon("play")}</button><button class="table-action">${icon("ellipsis")}</button></td></tr>`,
    )
    .join("");
  app.innerHTML = `
    ${pageHead("settings", `<button class="primary-action">${icon("plus")}添加模型</button>`)}
    <section class="config-layout">
      <div>
        ${tableShell(["模型名称", "模型类型", "提供商", "模型版本", "状态", "上下文窗口", "最大输出长度", "温度", "操作"], rows, "注：已启用的模型将按照优先级顺序在多Agent协作过程中被调用")}
        <section class="panel">
          <div class="panel-title"><h2>API密钥配置</h2><button class="small-btn">${icon("plus")}添加API</button></div>
          ${tableShell(["服务商", "API Key", "剩余额度", "请求限制", "状态", "操作"], ["DeepSeek", "阿里云通义", "OpenAI", "Anthropic"].map((x, i) => `<tr><td>${x}</td><td>sk-${x.toLowerCase().slice(0, 3)}-****************${["89ab", "43ef", "6d7a", "b7c1"][i]}</td><td>${["2.15M tokens", "1.32M tokens", "982K tokens", "已过期"][i]}</td><td>${[50, 60, 40, 20][i]} RPM</td><td><span class="badge ${i === 3 ? "high" : "ok"}">${i === 3 ? "异常" : "正常"}</span></td><td><button class="table-action">${icon("eye")}</button><button class="table-action">${icon("pencil")}</button></td></tr>`).join(""), "")}
        </section>
      </div>
      <aside class="right-stack">
        <section class="config-card">
          <div class="panel-title"><h2>模型全局配置</h2></div>
          <div class="form-grid">
            ${[["默认模型", "DeepSeek-R1"], ["模型调用策略", "优先级轮询"], ["请求超时时间", "120 秒"], ["最大重试次数", "3 次"]].map(([l, v]) => `<div class="field"><label>${l}</label><input value="${v}" /></div>`).join("")}
            <div class="field"><label>温度</label><input class="range" type="range" min="0" max="1" step=".1" value=".3" /></div>
            <div class="field"><label>Top P</label><input class="range" type="range" min="0" max="1" step=".1" value=".9" /></div>
            <button class="primary-action" style="width:100%">${icon("save")}保存全局配置</button>
          </div>
        </section>
        <section class="config-card">
          <div class="panel-title"><h2>模型测试</h2></div>
          <div class="form-grid">
            <div class="field"><label>选择模型</label><input value="DeepSeek-R1" /></div>
            <div class="field"><label>测试提示</label><textarea>请分析以下代码是否存在潜在的越界写入漏洞：memcpy(buf, user_input, len);</textarea></div>
            <button class="ghost-btn">${icon("play")}运行测试</button>
            <p class="page-subtitle"><span class="dot ok"></span> 连接正常，响应时间：1.42s</p>
          </div>
        </section>
      </aside>
    </section>
  `;
}

function renderReports() {
  const rows = reports
    .map(
      (r, i) => `<tr><td><b>${r[0]}</b><br><span style="color:var(--muted)">报告ID: ${r[1]} <span class="badge info">v1.0</span></span></td><td>${r[2]}</td><td>${r[3]}</td><td><span style="color:var(--red)">${r[4]}</span></td><td><span style="color:var(--orange)">${r[5]}</span></td><td><span style="color:var(--blue-2)">${r[6]}</span></td><td>${r[7]}</td><td>${r[8]}</td><td><span class="badge ok">${r[9]}</span></td><td><button class="table-action">${icon("eye")}</button><button class="table-action">${icon("download")}</button><button class="table-action">${icon("ellipsis")}</button></td></tr>`,
    )
    .join("");
  app.innerHTML = `
    ${pageHead("reports", `<button class="ghost-btn">${icon("rotate-cw")}重置</button><button class="primary-action">${icon("file-plus")}生成报告</button>`)}
    ${statCards([
      ["报告总数", "128", "较上次 ↑ 18.5%", "file-chart-column", ""],
      ["本月生成", "24", "较上月 ↑ 26.7%", "list-filter", "purple"],
      ["高危漏洞", "386", "较上月 ↑ 15.3%", "triangle-alert", "red"],
      ["已修复漏洞", "152", "较上月 ↑ 22.1%", "shield-check", "green"],
      ["报告下载量", "89", "较上月 ↑ 12.6%", "download", ""],
    ])}
    ${searchRow(`<button class="primary-action">${icon("file-plus")}生成报告</button>`)}
    <section class="report-layout">
      <div>${tableShell(["报告信息", "所属项目", "报告类型", "高危", "中危", "低危", "总数", "生成时间", "状态", "操作"], rows, "共 128 条")}</div>
      <aside class="right-stack">
        <section class="panel">
          <div class="panel-title"><h2>报告预览</h2><button class="small-btn">${icon("external-link")}查看完整报告</button></div>
          <div class="insight">
            <div class="score-medal">${icon("file-text")}</div>
            <p><b>Linux Kernel 6.6.0 漏洞检测报告</b><br>报告版本 v1.0，大小 3.24MB，共 42 页。</p>
          </div>
        </section>
        ${donutPanel("漏洞等级分布")}
        <section class="panel"><div class="panel-title"><h2>漏洞类型 TOP 5</h2></div>${["CWE-787 越界写入", "CWE-476 空指针引用", "CWE-416 释放后使用", "CWE-79 跨站脚本", "CWE-89 SQL注入"].map((x, i) => `<div class="legend-row"><span class="swatch ${["red", "orange", "yellow", "green", "purple"][i]}"></span><span>${x}</span><b>${[186, 142, 116, 98, 72][i]}</b></div>`).join("")}</section>
      </aside>
    </section>
  `;
}

function renderDocs() {
  app.innerHTML = `
    ${pageHead("docs")}
    <section class="docs-layout">
      <aside class="panel doc-nav">
        <label class="search-box">${icon("search")}<input placeholder="搜索文档内容..." /></label>
        <div class="doc-list">
          ${["1. 快速开始", "2. 系统概述", "3. 功能指南", "4. 配置说明", "5. 使用技巧", "6. 常见问题", "7. 更新日志"].map((x, i) => `<a class="${i === 0 ? "is-active" : ""}" href="#">${x}</a>`).join("")}
        </div>
      </aside>
      <article class="panel article">
        <h2>1. 快速开始</h2>
        <p>本章将帮助你快速了解 VulSage 智擎多Agent漏洞检测系统的基本使用流程。</p>
        <h3>1.1 系统使用流程</h3>
        <div class="doc-flow">
          ${[["创建项目", "folder"], ["配置检测", "settings"], ["运行检测", "play-circle"], ["查看结果", "file-text"], ["深度分析", "line-chart"]].map(([x, ic], i) => `<article class="flow-card"><div class="step">${icon(ic)}</div><b>${x}</b><small>${["导入或选择源码", "选择范围和规则", "启动多Agent协同", "查看报告和证据", "定位关键风险"][i]}</small></article>`).join("")}
        </div>
        <h3>1.2 创建检测任务</h3>
        <ol>
          <li>进入项目管理页面，选择已有项目或新建项目。</li>
          <li>在项目详情中点击新建检测任务。</li>
          <li>配置检测范围、检测级别和相关选项。</li>
          <li>点击开始检测，系统将自动调度多Agent执行检测流程。</li>
        </ol>
        <div class="summary-box"><b>提示：</b>检测时间取决于项目规模和复杂度，系统会智能分配资源以提高检测效率。</div>
      </article>
      <aside class="right-stack">
        <section class="panel"><div class="panel-title"><h2>本文档内容</h2></div><div class="doc-list">${["1. 快速开始", "1.1 系统使用流程", "1.2 创建检测任务", "1.3 查看检测结果", "1.4 系统要求"].map((x) => `<a href="#">${x}</a>`).join("")}</div></section>
        <section class="panel"><div class="panel-title"><h2>常见问题</h2></div><div class="legend">${["如何提高检测准确率？", "支持哪些编程语言？", "如何处理误报？", "如何导出检测报告？"].map((x) => `<div class="legend-row"><span class="swatch"></span><span>${x}</span><b>${icon("arrow-right")}</b></div>`).join("")}</div></section>
      </aside>
    </section>
  `;
}

function renderPage(key) {
  const renderers = {
    overview: renderOverview,
    projects: renderProjects,
    analysis: renderAnalysis,
    tasks: renderTasks,
    results: renderResults,
    agents: renderAgents,
    settings: renderSettings,
    reports: renderReports,
    docs: renderDocs,
  };
  (renderers[key] || renderOverview)();
  document.querySelectorAll(".nav-item").forEach((btn) => btn.classList.toggle("is-active", btn.dataset.page === key));
  app.scrollTo({ top: 0, behavior: "auto" });
  refreshIcons();
}

function setRoute(key) {
  const url = new URL(window.location.href);
  url.searchParams.set("page", key);
  window.history.replaceState({}, "", url);
}

document.addEventListener("click", (event) => {
  const actionButton = event.target.closest("[data-action='new-scan'], .primary-action");
  if (actionButton && /新建检测|开始检测/.test(actionButton.textContent || "")) {
    document.body.classList.add("drawer-open");
    const drawer = document.querySelector(".scan-drawer");
    drawer?.setAttribute("aria-hidden", "false");
    refreshIcons();
    return;
  }

  if (event.target.closest("[data-close-drawer]")) {
    document.body.classList.remove("drawer-open");
    document.querySelector(".scan-drawer")?.setAttribute("aria-hidden", "true");
    return;
  }

  const link = event.target.closest("[data-page]");
  if (!link) return;
  event.preventDefault();
  setRoute(link.dataset.page);
  renderPage(link.dataset.page);
});

document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const initialPage = params.get("page") || window.location.hash.replace("#", "") || "overview";
  renderPage(pages[initialPage] ? initialPage : "overview");
});

// MVP data layer: real API first, static demo as offline fallback.
const baseRenderers = {
  projects: renderProjects,
  analysis: renderAnalysis,
  settings: renderSettings,
  docs: renderDocs,
};

const mvpState = {
  loaded: false,
  apiOk: false,
  loading: false,
  currentPage: "overview",
  data: null,
  lastError: "",
  activeJobId: "",
};

const severityRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function textOr(value, fallback = "-") {
  return value === undefined || value === null || value === "" ? fallback : String(value);
}

function htmlEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function compactNumber(value) {
  const n = Number(value || 0);
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function sevTone(severity) {
  if (severity === "critical" || severity === "high" || severity === "高危") return "high";
  if (severity === "medium" || severity === "中危") return "mid";
  if (severity === "low" || severity === "低危") return "low";
  return "info";
}

function sevLabel(severity) {
  return {
    critical: "严重",
    high: "高危",
    medium: "中危",
    low: "低危",
    info: "提示",
  }[severity] || textOr(severity, "中危");
}

function statusTone(status) {
  const s = String(status || "").toLowerCase();
  if (s.includes("fail") || s.includes("失败") || s.includes("error")) return "high";
  if (s.includes("complete") || s.includes("done") || s.includes("已完成") || s.includes("确认")) return "ok";
  if (s.includes("run") || s.includes("运行")) return "info";
  return "mid";
}

async function fetchJson(endpoint, options = {}) {
  const response = await fetch(endpoint, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `${response.status} ${response.statusText}`);
  return body;
}

async function loadMvpData({ force = false } = {}) {
  if (mvpState.loading) return mvpState.data;
  if (mvpState.loaded && !force) return mvpState.data;
  mvpState.loading = true;
  try {
    const data = await fetchJson("/api/summary");
    mvpState.data = data;
    mvpState.apiOk = true;
    mvpState.loaded = true;
    mvpState.lastError = "";
    sessionStorage.setItem("vulnsage:last-summary", JSON.stringify(data));
  } catch (error) {
    const cached = sessionStorage.getItem("vulnsage:last-summary");
    mvpState.data = cached ? JSON.parse(cached) : null;
    mvpState.apiOk = Boolean(cached);
    mvpState.loaded = true;
    mvpState.lastError = error.message || "API unavailable";
  } finally {
    mvpState.loading = false;
  }
  return mvpState.data;
}

function dataSourceBadge() {
  if (!mvpState.loaded) return `<span class="data-source">${icon("loader")}正在连接 API</span>`;
  if (!mvpState.apiOk) return `<span class="data-source">${icon("wifi-off")}离线演示数据</span>`;
  const source = mvpState.data?.source === "real" ? "真实扫描数据" : "真实空数据";
  return `<span class="data-source">${icon(mvpState.data?.source === "real" ? "database" : "database-zap")}${source}</span>`;
}

function apiStats() {
  const s = mvpState.data?.stats || {};
  const severity = s.severity_summary || {};
  return {
    totalFiles: Number(s.total_files || 0),
    totalVulns: Number(s.total_vulnerabilities || 0),
    high: Number(severity.critical || 0) + Number(severity.high || 0),
    medium: Number(severity.medium || 0),
    low: Number(severity.low || 0),
    confirmed: Number(s.confirmed || 0),
    reports: Number(s.total_reports || 0),
    running: Number(s.running_jobs || 0),
    completed: Number(s.completed_jobs || 0),
    failed: Number(s.failed_jobs || 0),
  };
}

function mvpStatCards(kind = "overview") {
  if (!mvpState.apiOk && !mvpState.data) return statCards();
  const s = apiStats();
  const maps = {
    overview: [
      ["检测文件", compactNumber(s.totalFiles), "来自 scan_summary.json", "file-text", ""],
      ["扫描任务", String(s.running + s.completed + s.failed), `运行中 ${s.running}`, "clipboard-check", "green"],
      ["发现漏洞", String(s.totalVulns), `高危 ${s.high} 个`, "shield-alert", "red"],
      ["报告数量", String(s.reports), "result/*.report.json", "file-chart-column", ""],
      ["已确认漏洞", String(s.confirmed), "由报告状态聚合", "badge-check", "green"],
    ],
    results: [
      ["漏洞总数", String(s.totalVulns), "真实报告聚合", "shield-alert", "red"],
      ["高危漏洞", String(s.high), "critical + high", "triangle-alert", "red"],
      ["中危漏洞", String(s.medium), "medium", "badge-alert", "orange"],
      ["低危漏洞", String(s.low), "low", "shield", "green"],
      ["已确认漏洞", String(s.confirmed), `报告 ${s.reports} 份`, "badge-check", "green"],
    ],
    tasks: [
      ["任务总数", String(s.running + s.completed + s.failed), "本次 Web 会话", "layers-3", ""],
      ["运行中", String(s.running), "扫描子进程", "play", "green"],
      ["已完成", String(s.completed), "退出码 0", "circle-check", "purple"],
      ["失败任务", String(s.failed), "非 0 或异常", "x", "red"],
      ["报告数量", String(s.reports), "可被前端读取", "file-chart-column", ""],
    ],
    reports: [
      ["报告总数", String(s.reports), "result/*.report.json", "file-chart-column", ""],
      ["漏洞总数", String(s.totalVulns), "全部报告聚合", "shield-alert", "red"],
      ["高危漏洞", String(s.high), "需要优先处理", "triangle-alert", "red"],
      ["已确认漏洞", String(s.confirmed), "报告内确认项", "shield-check", "green"],
      ["扫描任务", String(s.running + s.completed + s.failed), "Web MVP 会话", "list-filter", "purple"],
    ],
  };
  return statCards(maps[kind] || maps.overview);
}

function realFindings() {
  if (mvpState.apiOk) return mvpState.data?.findings || [];
  return findings.map((f, idx) => ({
    id: `mock-${idx}`,
    vuln_id: f[0],
    severity_label: f[1],
    severity: f[1] === "高危" ? "high" : f[1] === "中危" ? "medium" : "low",
    cwe: f[2],
    file: f[3],
    line: f[4],
    location: `line ${f[4]}`,
    function_name: f[5],
    source: f[6],
    status: f[7],
    confidence: f[8],
    description: "演示漏洞详情。启动 Web MVP 后端并运行扫描后，这里会显示 result/ 中的真实报告内容。",
    suggestion: "运行一次扫描或放入真实 *.report.json。",
  }));
}

function realReports() {
  if (mvpState.apiOk) return mvpState.data?.reports || [];
  return reports.map((r, idx) => ({
    id: `mock-report-${idx}`,
    file: r[0],
    project: r[2],
    total_vulnerabilities: r[7],
    scan_time: r[8],
    severity_summary: { high: r[4], medium: r[5], low: r[6] },
    path: "演示报告",
  }));
}

function realJobs() {
  if (mvpState.apiOk) return mvpState.data?.scans || [];
  return tasks.map((t, idx) => ({
    id: t[0],
    status: idx < 2 ? "running" : idx < 4 ? "completed" : "failed",
    command_display: t[1],
    created_at: "2025-06-01 14:32:45",
    duration_sec: idx < 2 ? 0 : 120 + idx * 30,
    returncode: idx < 4 ? 0 : 1,
    pid: idx < 2 ? 10000 + idx : null,
  }));
}

function emptyState(title, body, action = true) {
  return `<section class="panel"><div class="empty-note"><b>${title}</b><br>${body}${action ? `<div style="margin-top:14px"><button class="primary-action" data-action="new-scan">${icon("play")}开始一次真实扫描</button></div>` : ""}</div></section>`;
}

function mvpVulnListPanel(items = realFindings().slice(0, 4)) {
  if (!items.length) return emptyState("暂无真实漏洞结果", "当前 result/ 目录还没有 *.report.json。可以发起扫描生成报告。");
  return `
    <section class="panel">
      <div class="panel-title">
        <h2>漏洞列表</h2>
        <button class="small-btn" data-page="results">查看全部 ${icon("arrow-right")}</button>
      </div>
      <div class="vuln-list">
        ${items
          .map((v) => {
            const tone = sevTone(v.severity);
            return `
          <article class="vuln-item ${tone}">
            <span class="badge ${tone}">${v.severity_label || sevLabel(v.severity)}</span>
            <div><b>${htmlEscape(v.cwe || v.cwe_description || "未知漏洞")}</b><small>${htmlEscape(v.file || "-")}:${htmlEscape(v.line || "-")}<br />${htmlEscape(v.description || v.location || "")}</small></div>
            <button class="small-btn" data-action="finding-detail" data-id="${htmlEscape(v.id)}">详情</button>
          </article>`;
          })
          .join("")}
      </div>
    </section>
  `;
}

function mvpOverview() {
  const s = apiStats();
  const actions = `${dataSourceBadge()}<button class="ghost-btn" data-action="refresh-data">${icon("refresh-cw")}刷新数据</button><button class="primary-action" data-action="new-scan">${icon("plus")}新建检测</button>`;
  app.innerHTML = `
    ${pageHead("overview", actions)}
    ${mvpStatCards("overview")}
    ${mvpState.apiOk && mvpState.data?.source === "empty" ? emptyState("还没有真实扫描报告", mvpState.data.message || "运行一次扫描后，统计卡、漏洞列表和报告页会自动切换为真实数据。") : ""}
    ${pipelineView()}
    <section class="work-grid">
      <div>
        ${codePanel()}
        ${graphPanel()}
        ${insightPanel()}
      </div>
      <aside class="right-stack">
        ${mvpDonutPanel("漏洞分布统计")}
        ${mvpVulnListPanel(realFindings().slice(0, 4))}
        <section class="panel">
          <div class="panel-title"><h2>真实数据状态</h2></div>
          <p class="page-subtitle">报告 ${s.reports} 份，漏洞 ${s.totalVulns} 个，当前运行任务 ${s.running} 个。</p>
          <div style="display:flex;gap:10px;margin-top:16px;flex-wrap:wrap">
            <button class="primary-action" data-action="new-scan">${icon("play")}开始扫描</button>
            <button class="ghost-btn" data-page="reports">${icon("file-text")}查看报告</button>
          </div>
        </section>
      </aside>
    </section>
  `;
}

function mvpDonutPanel(title, alt = false) {
  const s = apiStats();
  const cwes = Object.entries(mvpState.data?.stats?.cwe_summary || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const total = alt ? s.reports : Math.max(1, s.totalVulns);
  const legend = alt
    ? [
        ["报告数量", `${s.reports}`, ""],
        ["运行任务", `${s.running}`, "green"],
        ["完成任务", `${s.completed}`, "purple"],
        ["失败任务", `${s.failed}`, "red"],
      ]
    : cwes.length
      ? cwes.map(([name, count], i) => [name, `${count} (${Math.round((count / total) * 100)}%)`, ["red", "orange", "yellow", "green", "purple"][i]])
      : [
          ["高危", `${s.high}`, "red"],
          ["中危", `${s.medium}`, "orange"],
          ["低危", `${s.low}`, "yellow"],
          ["提示", "0", ""],
        ];
  return `
    <section class="panel">
      <div class="panel-title"><h2>${title}</h2></div>
      <div class="donut-wrap">
        <div class="donut ${alt ? "alt" : ""}" data-label="${alt ? `${s.reports}&#10;报告` : `${s.totalVulns}&#10;总计`}"></div>
        <div class="legend">
          ${legend
            .map(([name, value, tone]) => `<div class="legend-row"><span class="swatch ${tone}"></span><span>${htmlEscape(name)}</span><b>${htmlEscape(value)}</b></div>`)
            .join("")}
        </div>
      </div>
    </section>
  `;
}

function mvpResults() {
  const rows = realFindings()
    .map((f) => {
      const tone = sevTone(f.severity);
      const confidence = typeof f.confidence === "number" ? `${f.confidence}%` : textOr(f.confidence, "-");
      return `
      <tr data-action="finding-detail" data-id="${htmlEscape(f.id)}">
        <td><input type="checkbox" /></td><td>${htmlEscape(f.vuln_id || f.id)}</td><td><span class="badge ${tone}">${htmlEscape(f.severity_label || sevLabel(f.severity))}</span></td>
        <td>${htmlEscape(f.cwe || f.cwe_description || "-")}</td><td>${htmlEscape(f.file || "-")}</td><td>${htmlEscape(f.line || "-")}</td><td>${htmlEscape(f.function_name || "-")}</td>
        <td><span class="badge info">${htmlEscape(f.source || "真实报告")}</span></td><td><span class="badge ${statusTone(f.status)}">${htmlEscape(f.status || "待确认")}</span></td><td>${confidence}</td>
        <td><button class="table-action" data-action="finding-detail" data-id="${htmlEscape(f.id)}">${icon("eye")}</button><button class="table-action" data-action="finding-evidence" data-id="${htmlEscape(f.id)}">${icon("git-branch")}</button></td>
      </tr>`;
    })
    .join("");
  app.innerHTML = `
    ${pageHead("results", `${dataSourceBadge()}<button class="ghost-btn" data-action="refresh-data">${icon("refresh-cw")}刷新</button><button class="primary-action" data-page="reports">${icon("file-down")}查看报告</button>`)}
    ${mvpStatCards("results")}
    ${searchRow()}
    ${realFindings().length ? `<section class="dashboard-grid"><div>${tableShell(["", "漏洞ID", "风险等级", "漏洞类型 (CWE)", "文件路径", "行号", "函数名", "检测来源", "状态", "置信度", "操作"], rows, `共 ${realFindings().length} 条真实漏洞`)}</div><aside class="right-stack"><section class="panel"><div class="panel-title"><h2>漏洞趋势</h2></div>${lineChart()}</section>${mvpDonutPanel("漏洞类型分布")}${mvpDonutPanel("报告来源分布", true)}</aside></section>` : emptyState("暂无真实漏洞结果", "运行扫描后，这里会展示真实漏洞列表、置信度、证据链和代码上下文。")}
  `;
}

function mvpTasks() {
  const jobs = realJobs();
  const rows = jobs
    .map((j) => {
      const status = j.status || "queued";
      const percent = status === "completed" || status === "failed" ? 100 : status === "running" ? 58 : 5;
      return `
        <tr data-action="scan-detail" data-id="${htmlEscape(j.id)}">
          <td><b>${htmlEscape(j.id)}</b><br><span style="color:var(--muted)">${htmlEscape(j.command_display || "扫描任务")}</span></td>
          <td>${htmlEscape(j.pid || "-")}</td><td>${htmlEscape(j.created_at || "-")}</td><td>${htmlEscape(j.started_at || "-")}</td>
          <td><span class="badge ${statusTone(status)}">${htmlEscape(status)}</span><div class="progress-cell"><div class="progress ${statusTone(status) === "high" ? "red" : ""}"><span style="width:${percent}%"></span></div><span>${percent}%</span></div></td>
          <td>${htmlEscape(j.duration_sec || 0)}s</td><td>${htmlEscape(j.returncode ?? "-")}</td>
          <td><button class="table-action" data-action="scan-detail" data-id="${htmlEscape(j.id)}">${icon("eye")}</button><button class="table-action" data-action="refresh-data">${icon("refresh-cw")}</button></td>
        </tr>`;
    })
    .join("");
  app.innerHTML = `
    ${pageHead("tasks", `${dataSourceBadge()}<button class="ghost-btn" data-action="refresh-data">${icon("refresh-cw")}刷新</button><button class="primary-action" data-action="new-scan">${icon("plus")}新建检测任务</button>`)}
    ${mvpStatCards("tasks")}
    ${searchRow(`<button class="primary-action" data-action="new-scan">${icon("plus")}新建检测任务</button>`)}
    ${jobs.length ? tableShell(["任务ID", "PID", "创建时间", "开始时间", "状态 / 进度", "耗时", "退出码", "操作"], rows, `共 ${jobs.length} 个任务`) : emptyState("暂无 Web 扫描任务", "点击“新建检测任务”即可由后端启动 python main.py 扫描。")}
    <section class="work-grid">
      <section class="panel"><div class="panel-title"><h2>任务执行趋势</h2></div>${lineChart()}</section>
      <section class="panel"><div class="panel-title"><h2>扫描状态占比</h2></div>${mvpDonutPanel("扫描状态占比", true)}</section>
    </section>
  `;
}

function mvpAgents() {
  const s = apiStats();
  const jobs = realJobs();
  const jobRows = jobs
    .slice(0, 6)
    .map(
      (j) => `<tr data-action="scan-detail" data-id="${htmlEscape(j.id)}"><td>${htmlEscape(j.id)}</td><td><span class="badge ${statusTone(j.status)}">${htmlEscape(j.status || "queued")}</span></td><td>${htmlEscape(j.pid || "-")}</td><td>${htmlEscape(j.duration_sec || 0)}s</td><td>${htmlEscape(j.returncode ?? "-")}</td><td><button class="table-action" data-action="scan-detail" data-id="${htmlEscape(j.id)}">${icon("eye")}</button></td></tr>`,
    )
    .join("");
  app.innerHTML = `
    ${pageHead("agents", `${dataSourceBadge()}<button class="ghost-btn" data-action="refresh-data">${icon("refresh-cw")}刷新</button><button class="ghost-btn" data-page="tasks">${icon("list-checks")}查看任务</button>`)}
    ${statCards([
      ["Agent总数", "6", "MVP 固定流水线", "bot", ""],
      ["运行任务", String(s.running), "来自后端子进程", "play", "green"],
      ["完成任务", String(s.completed), "本次 Web 会话", "circle-check", "purple"],
      ["失败任务", String(s.failed), "查看任务日志定位", "triangle-alert", "red"],
      ["报告数量", String(s.reports), "result/ 真实报告", "file-chart-column", ""],
    ])}
    <section class="panel">
      <div class="panel-title"><h2>多Agent执行流程</h2><p>真实扫描由 CLI 后端驱动</p></div>
      <div class="agent-flow">${agents.map((a, i) => `<article class="agent-step"><span class="step">${icon(pipeline[i % pipeline.length][2])}</span><b>${pipeline[i % pipeline.length][0]}</b><small>${s.running ? "运行中" : "待命"} · 阶段 ${i + 1}/6</small><div class="meter green"><span style="width:${s.running ? 42 + i * 8 : 12}%"></span></div></article>`).join("")}</div>
    </section>
    <section class="dashboard-grid">
      <div>${jobs.length ? tableShell(["任务ID", "状态", "PID", "耗时", "退出码", "操作"], jobRows, `最近 ${jobs.length} 个任务`) : emptyState("暂无任务", "启动一次真实扫描后，这里会展示后端子进程和日志。")}</div>
      <aside class="right-stack"><section class="panel"><div class="panel-title"><h2>实时资源消耗趋势</h2></div>${lineChart()}</section>${mvpDonutPanel("Token消耗分布", true)}</aside>
    </section>
  `;
}

function mvpReports() {
  const items = realReports();
  const rows = items
    .map((r) => {
      const sev = r.severity_summary || {};
      return `<tr data-action="report-detail" data-id="${htmlEscape(r.id)}">
        <td><b>${htmlEscape(r.file || r.path || r.id)}</b><br><span style="color:var(--muted)">报告ID: ${htmlEscape(r.id)} <span class="badge info">JSON</span></span></td>
        <td>${htmlEscape(r.project || "-")}</td><td>检测报告</td><td><span style="color:var(--red)">${Number(sev.critical || 0) + Number(sev.high || 0)}</span></td>
        <td><span style="color:var(--orange)">${Number(sev.medium || 0)}</span></td><td><span style="color:var(--blue-2)">${Number(sev.low || 0)}</span></td>
        <td>${htmlEscape(r.total_vulnerabilities || 0)}</td><td>${htmlEscape(r.scan_time || "-")}</td><td><span class="badge ok">可读取</span></td>
        <td><button class="table-action" data-action="report-detail" data-id="${htmlEscape(r.id)}">${icon("eye")}</button><button class="table-action" data-action="report-detail" data-id="${htmlEscape(r.id)}">${icon("download")}</button></td>
      </tr>`;
    })
    .join("");
  app.innerHTML = `
    ${pageHead("reports", `${dataSourceBadge()}<button class="ghost-btn" data-action="refresh-data">${icon("refresh-cw")}刷新</button><button class="primary-action" data-action="new-scan">${icon("file-plus")}生成报告</button>`)}
    ${mvpStatCards("reports")}
    ${searchRow(`<button class="primary-action" data-action="new-scan">${icon("file-plus")}生成报告</button>`)}
    ${items.length ? `<section class="report-layout"><div>${tableShell(["报告信息", "所属项目", "报告类型", "高危", "中危", "低危", "总数", "生成时间", "状态", "操作"], rows, `共 ${items.length} 份报告`)}</div><aside class="right-stack">${mvpDonutPanel("漏洞等级分布")}<section class="panel"><div class="panel-title"><h2>报告操作</h2></div><div class="drawer-agents"><button class="small-btn" data-action="new-scan">${icon("refresh-cw")}重新生成</button><button class="small-btn" data-action="refresh-data">${icon("database")}重读 result/</button></div></section></aside></section>` : emptyState("暂无真实报告", "扫描结束后，后端会从 result/*.report.json 读取报告并在这里展示。")}
  `;
}

async function renderPage(key) {
  mvpState.currentPage = key;
  if (!mvpState.loaded) {
    app.innerHTML = `${pageHead(key)}${emptyState("正在连接后端 API", "如果你是直接打开 HTML，将自动使用离线演示数据。", false)}`;
    refreshIcons();
    await loadMvpData();
  }
  const mvpRenderers = {
    overview: mvpOverview,
    results: mvpResults,
    tasks: mvpTasks,
    agents: mvpAgents,
    reports: mvpReports,
  };
  if (mvpRenderers[key]) {
    mvpRenderers[key]();
  } else {
    (baseRenderers[key] || renderOverview)();
  }
  document.querySelectorAll(".nav-item").forEach((btn) => btn.classList.toggle("is-active", btn.dataset.page === key));
  app.scrollTo({ top: 0, behavior: "auto" });
  refreshIcons();
}

function openDrawerHtml(html) {
  const drawer = document.querySelector(".scan-drawer");
  if (!drawer) return;
  drawer.innerHTML = html;
  drawer.setAttribute("aria-hidden", "false");
  document.body.classList.add("drawer-open");
  refreshIcons();
}

function closeDrawer() {
  document.body.classList.remove("drawer-open");
  document.querySelector(".scan-drawer")?.setAttribute("aria-hidden", "true");
}

function openScanDrawer() {
  openDrawerHtml(`
    <div class="drawer-head">
      <div><span class="eyebrow">Backend Scan</span><h2>新建真实扫描任务</h2></div>
      <button class="icon-btn" data-close-drawer aria-label="关闭">${icon("x")}</button>
    </div>
    <div class="form-grid">
      <div class="field field-vertical"><label>运行模式</label><select id="scan-mode"><option value="scan">工程级扫描 scan</option><option value="detect">单文件检测 detect</option></select></div>
      <div class="field field-vertical"><label>扫描路径 / 文件</label><input id="scan-root" value="dataset/multi_c_project" /></div>
      <div class="field field-vertical"><label>并行度</label><input id="scan-parallel" type="number" min="1" max="16" value="2" /></div>
      <div class="field field-vertical"><label>最大文件数</label><input id="scan-max-files" type="number" min="1" placeholder="可留空" /></div>
      <label class="drawer-section" style="display:flex;align-items:center;gap:10px"><input id="scan-cpg" type="checkbox" /> 启用 workspace CPG</label>
      <div class="drawer-section">
        <h3>执行说明</h3>
        <p class="page-subtitle">后端会运行 <code>python main.py</code>。扫描结果写入 result/，完成后页面会自动刷新真实数据。</p>
      </div>
      <button class="primary-action drawer-submit" data-action="start-scan">${icon("play")}开始检测</button>
    </div>
  `);
}

async function startScanFromDrawer() {
  const mode = document.querySelector("#scan-mode")?.value || "scan";
  const root = document.querySelector("#scan-root")?.value || "dataset/multi_c_project";
  const payload = {
    mode,
    parallel: Number(document.querySelector("#scan-parallel")?.value || 2),
    max_files: document.querySelector("#scan-max-files")?.value || undefined,
    c_workspace_cpg: Boolean(document.querySelector("#scan-cpg")?.checked),
  };
  if (mode === "scan") payload.root = root;
  else {
    payload.source = "local";
    payload.file = root;
  }
  openDrawerHtml(`
    <div class="drawer-head"><div><span class="eyebrow">Starting</span><h2>正在启动扫描</h2></div><button class="icon-btn" data-close-drawer>${icon("x")}</button></div>
    <div class="drawer-section"><p class="page-subtitle">后端正在创建子进程，请稍候...</p></div>
  `);
  try {
    const job = await fetchJson("/api/scans", { method: "POST", body: JSON.stringify(payload) });
    mvpState.activeJobId = job.id;
    await loadMvpData({ force: true });
    await renderPage("tasks");
    openScanDetail(job.id);
  } catch (error) {
    openDrawerHtml(`<div class="drawer-head"><div><span class="eyebrow">Error</span><h2>启动失败</h2></div><button class="icon-btn" data-close-drawer>${icon("x")}</button></div><div class="drawer-section"><p class="page-subtitle">${htmlEscape(error.message)}</p></div>`);
  }
}

async function openScanDetail(id) {
  try {
    const job = mvpState.apiOk ? await fetchJson(`/api/scans/${encodeURIComponent(id)}`) : realJobs().find((j) => j.id === id);
    openDrawerHtml(`
      <div class="drawer-head"><div><span class="eyebrow">Scan Job</span><h2>任务详情</h2></div><button class="icon-btn" data-close-drawer>${icon("x")}</button></div>
      <div class="detail-grid">
        ${[["任务ID", job.id], ["状态", job.status], ["PID", job.pid || "-"], ["退出码", job.returncode ?? "-"], ["创建时间", job.created_at || "-"], ["耗时", `${job.duration_sec || 0}s`]].map(([a, b]) => `<div class="detail-item"><span>${a}</span><b>${htmlEscape(b)}</b></div>`).join("")}
      </div>
      <div class="drawer-section"><h3>执行命令</h3><div class="log-box">${htmlEscape(job.command_display || "")}</div></div>
      <div class="drawer-section"><h3>日志尾部</h3><div class="log-box">${htmlEscape(job.log_tail || "暂无日志")}</div></div>
      <button class="ghost-btn drawer-submit" data-action="refresh-job" data-id="${htmlEscape(id)}">${icon("refresh-cw")}刷新任务</button>
    `);
  } catch (error) {
    openDrawerHtml(`<div class="drawer-head"><div><span class="eyebrow">Error</span><h2>读取任务失败</h2></div><button class="icon-btn" data-close-drawer>${icon("x")}</button></div><div class="drawer-section">${htmlEscape(error.message)}</div>`);
  }
}

async function openFindingDetail(id) {
  const finding = realFindings().find((f) => String(f.id) === String(id));
  if (!finding) return;
  let context = null;
  if (mvpState.apiOk && finding.file) {
    try {
      context = await fetchJson(`/api/code-context?file=${encodeURIComponent(finding.file)}&line=${encodeURIComponent(finding.line || 1)}&radius=8`);
    } catch {
      context = null;
    }
  }
  openDrawerHtml(`
    <div class="drawer-head"><div><span class="eyebrow">Finding Detail</span><h2>${htmlEscape(finding.cwe || "漏洞详情")}</h2></div><button class="icon-btn" data-close-drawer>${icon("x")}</button></div>
    <div class="detail-grid">
      ${[["风险等级", finding.severity_label || sevLabel(finding.severity)], ["置信度", finding.confidence || "-"], ["文件", finding.file || "-"], ["行号", finding.line || "-"], ["状态", finding.status || "-"], ["报告ID", finding.report_id || "-"]].map(([a, b]) => `<div class="detail-item"><span>${a}</span><b>${htmlEscape(b)}</b></div>`).join("")}
    </div>
    <div class="drawer-section"><h3>漏洞描述</h3><p class="page-subtitle">${htmlEscape(finding.description || "报告中暂无描述")}</p></div>
    <div class="drawer-section"><h3>修复建议</h3><p class="page-subtitle">${htmlEscape(finding.suggestion || "报告中暂无修复建议")}</p></div>
    <div class="drawer-section"><h3>代码上下文</h3><div class="code-context">${
      context?.found
        ? context.lines.map((l) => `<span class="${l.hit ? "hit" : ""}">${String(l.number).padStart(5, " ")}  ${htmlEscape(l.text)}</span>`).join("\n")
        : "未找到本地源码上下文。报告文件名可能不是仓库内相对路径。"
    }</div></div>
  `);
}

async function openReportDetail(id) {
  try {
    const report = mvpState.apiOk ? await fetchJson(`/api/reports/${encodeURIComponent(id)}`) : realReports().find((r) => r.id === id);
    const raw = report.raw || report;
    openDrawerHtml(`
      <div class="drawer-head"><div><span class="eyebrow">Report Preview</span><h2>报告详情</h2></div><button class="icon-btn" data-close-drawer>${icon("x")}</button></div>
      <div class="detail-grid">
        ${[["报告ID", report.id], ["项目", report.project], ["文件", report.file], ["漏洞数", report.total_vulnerabilities], ["扫描时间", report.scan_time || "-"], ["路径", report.path || "-"]].map(([a, b]) => `<div class="detail-item"><span>${a}</span><b>${htmlEscape(b)}</b></div>`).join("")}
      </div>
      <div class="drawer-section"><h3>CWE 分布</h3><div class="legend">${Object.entries(report.vulnerabilities_by_cwe || {}).map(([k, v]) => `<div class="legend-row"><span class="swatch"></span><span>${htmlEscape(k)}</span><b>${htmlEscape(v)}</b></div>`).join("") || "暂无 CWE 数据"}</div></div>
      <div class="drawer-section"><h3>原始 JSON 预览</h3><div class="log-box">${htmlEscape(JSON.stringify(raw, null, 2).slice(0, 8000))}</div></div>
    `);
  } catch (error) {
    openDrawerHtml(`<div class="drawer-head"><div><span class="eyebrow">Error</span><h2>读取报告失败</h2></div><button class="icon-btn" data-close-drawer>${icon("x")}</button></div><div class="drawer-section">${htmlEscape(error.message)}</div>`);
  }
}

document.addEventListener(
  "click",
  async (event) => {
    const target = event.target.closest("[data-action], [data-close-drawer]");
    if (!target) return;
    const action = target.dataset.action;
    if (target.matches("[data-close-drawer]")) {
      event.preventDefault();
      event.stopPropagation();
      closeDrawer();
      return;
    }
    if (["new-scan", "start-scan", "refresh-data", "scan-detail", "refresh-job", "finding-detail", "finding-evidence", "report-detail"].includes(action)) {
      event.preventDefault();
      event.stopPropagation();
    }
    if (action === "new-scan") openScanDrawer();
    if (action === "start-scan") await startScanFromDrawer();
    if (action === "refresh-data") {
      await loadMvpData({ force: true });
      await renderPage(mvpState.currentPage);
    }
    if (action === "scan-detail" || action === "refresh-job") await openScanDetail(target.dataset.id);
    if (action === "finding-detail" || action === "finding-evidence") await openFindingDetail(target.dataset.id);
    if (action === "report-detail") await openReportDetail(target.dataset.id);
  },
  true,
);

setInterval(async () => {
  if (!mvpState.apiOk) return;
  const running = (mvpState.data?.scans || []).some((j) => j.status === "running" || j.status === "queued");
  if (!running) return;
  await loadMvpData({ force: true });
  if (["overview", "tasks", "agents"].includes(mvpState.currentPage)) await renderPage(mvpState.currentPage);
}, 4000);

// Production interaction layer. It keeps the original visual shell, but makes the
// real-data pages URL-driven, filterable, pageable, and deep-linkable.
(() => {
  const VALID_PAGES = new Set(Object.keys(pages));
  const MVP_PAGES = new Set(["overview", "results", "tasks", "agents", "reports"]);
  const FILTERED_PAGES = new Set(["results", "tasks", "reports"]);
  const DEFAULT_FILTERS = {
    results: { q: "", severity: "all", status: "all", pageNo: 1, pageSize: 10 },
    tasks: { q: "", status: "all", pageNo: 1, pageSize: 10 },
    reports: { q: "", severity: "all", pageNo: 1, pageSize: 10 },
  };
  const PROD_ACTIONS = new Set([
    "new-scan",
    "start-scan",
    "refresh-data",
    "scan-detail",
    "refresh-job",
    "finding-detail",
    "finding-evidence",
    "report-detail",
    "clear-filters",
    "page-prev",
    "page-next",
    "page-set",
    "not-implemented",
  ]);

  Object.assign(mvpState, {
    dataOrigin: "mock",
    loadPromise: null,
    filters: structuredCloneSafe(DEFAULT_FILTERS),
    activeDrawer: null,
    drawerTimer: null,
    filterTimer: null,
    pendingFilterFocus: null,
    lastRefreshAt: "",
  });

  function structuredCloneSafe(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function clampNumber(value, min, max, fallback) {
    const n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, Math.trunc(n)));
  }

  function readUrlState() {
    const params = new URLSearchParams(window.location.search);
    const page = VALID_PAGES.has(params.get("page")) ? params.get("page") : window.location.hash.replace("#", "") || "overview";
    return {
      page: VALID_PAGES.has(page) ? page : "overview",
      q: params.get("q") || "",
      severity: params.get("severity") || "all",
      status: params.get("status") || "all",
      pageNo: clampNumber(params.get("pageNo"), 1, 9999, 1),
      pageSize: clampNumber(params.get("pageSize"), 5, 50, 10),
      drawer: params.get("drawer") || "",
      id: params.get("id") || "",
    };
  }

  function writeUrlState(patch = {}, { replace = false } = {}) {
    const url = new URL(window.location.href);
    const next = { ...readUrlState(), ...patch };
    const page = VALID_PAGES.has(next.page) ? next.page : "overview";
    url.searchParams.set("page", page);
    ["q", "severity", "status", "pageNo", "pageSize", "drawer", "id"].forEach((key) => {
      const value = next[key];
      const isDefault =
        value === undefined ||
        value === null ||
        value === "" ||
        (key === "severity" && value === "all") ||
        (key === "status" && value === "all") ||
        (key === "pageNo" && Number(value) === 1) ||
        (key === "pageSize" && Number(value) === 10);
      if (isDefault) url.searchParams.delete(key);
      else url.searchParams.set(key, String(value));
    });
    window.history[replace ? "replaceState" : "pushState"]({}, "", url);
  }

  function applyUrlToState() {
    const route = readUrlState();
    mvpState.currentPage = route.page;
    if (FILTERED_PAGES.has(route.page)) {
      mvpState.filters[route.page] = {
        ...mvpState.filters[route.page],
        q: route.q,
        pageNo: route.pageNo,
        pageSize: route.pageSize,
      };
      if ("severity" in mvpState.filters[route.page]) mvpState.filters[route.page].severity = route.severity;
      if ("status" in mvpState.filters[route.page]) mvpState.filters[route.page].status = route.status;
    }
    mvpState.activeDrawer = route.drawer && route.id ? { type: route.drawer, id: route.id } : null;
    return route;
  }

  function updateRouteFromFilter(page, { replace = true } = {}) {
    const filter = mvpState.filters[page] || {};
    writeUrlState(
      {
        page,
        q: filter.q || "",
        severity: filter.severity || "all",
        status: filter.status || "all",
        pageNo: filter.pageNo || 1,
        pageSize: filter.pageSize || 10,
        drawer: "",
        id: "",
      },
      { replace },
    );
  }

  function navigateToPage(page, { replace = false } = {}) {
    if (!VALID_PAGES.has(page)) page = "overview";
    clearDrawerPoll();
    writeUrlState({ page, q: "", severity: "all", status: "all", pageNo: 1, pageSize: 10, drawer: "", id: "" }, { replace });
    return renderPage(page);
  }

  setRoute = function productionSetRoute(page) {
    return navigateToPage(page, { replace: false });
  };

  function toast(message, tone = "info") {
    let root = document.querySelector(".toast-root");
    if (!root) {
      root = document.createElement("div");
      root.className = "toast-root";
      root.setAttribute("aria-live", "polite");
      document.body.appendChild(root);
    }
    const item = document.createElement("div");
    item.className = `toast ${tone}`;
    item.innerHTML = `<span>${htmlEscape(message)}</span><button type="button" aria-label="关闭">${icon("x")}</button>`;
    root.appendChild(item);
    refreshIcons();
    item.querySelector("button")?.addEventListener("click", () => item.remove());
    window.setTimeout(() => item.classList.add("is-visible"), 20);
    window.setTimeout(() => {
      item.classList.remove("is-visible");
      window.setTimeout(() => item.remove(), 180);
    }, 3600);
  }

  fetchJson = async function productionFetchJson(endpoint, options = {}) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), options.timeout || 15000);
    try {
      const headers = { Accept: "application/json", ...(options.headers || {}) };
      if (options.body && !(options.body instanceof FormData)) headers["Content-Type"] = headers["Content-Type"] || "application/json";
      const response = await fetch(endpoint, { ...options, headers, signal: controller.signal });
      const text = await response.text();
      const body = text ? JSON.parse(text) : {};
      if (!response.ok) throw new Error(body.error || body.message || `${response.status} ${response.statusText}`);
      return body;
    } catch (error) {
      if (error.name === "AbortError") throw new Error("API 请求超时，请确认后端服务仍在运行");
      if (error instanceof SyntaxError) throw new Error("API 返回了无法解析的数据");
      throw error;
    } finally {
      window.clearTimeout(timeout);
    }
  };

  loadMvpData = async function productionLoadMvpData({ force = false } = {}) {
    if (mvpState.loadPromise) return mvpState.loadPromise;
    if (mvpState.loaded && !force) return mvpState.data;
    mvpState.loading = true;
    mvpState.loadPromise = (async () => {
      try {
        const data = await fetchJson("/api/summary", { timeout: 12000 });
        mvpState.data = data;
        mvpState.apiOk = true;
        mvpState.dataOrigin = data?.source === "real" || data?.source === "empty" ? "api" : "api";
        mvpState.loaded = true;
        mvpState.lastError = "";
        mvpState.lastRefreshAt = new Date().toLocaleTimeString();
        sessionStorage.setItem("vulnsage:last-summary", JSON.stringify(data));
      } catch (error) {
        const cached = sessionStorage.getItem("vulnsage:last-summary");
        mvpState.data = cached ? JSON.parse(cached) : null;
        mvpState.apiOk = false;
        mvpState.dataOrigin = cached ? "cache" : "mock";
        mvpState.loaded = true;
        mvpState.lastError = error.message || "API unavailable";
      } finally {
        mvpState.loading = false;
        mvpState.loadPromise = null;
      }
      return mvpState.data;
    })();
    return mvpState.loadPromise;
  };

  dataSourceBadge = function productionDataSourceBadge() {
    if (!mvpState.loaded) return `<span class="data-source">${icon("loader")}正在连接 API</span>`;
    if (mvpState.apiOk) {
      const label = mvpState.data?.source === "real" ? "真实数据" : "API 在线 / 暂无报告";
      return `<span class="data-source">${icon("database")}${label}${mvpState.lastRefreshAt ? ` · ${htmlEscape(mvpState.lastRefreshAt)}` : ""}</span>`;
    }
    if (mvpState.dataOrigin === "cache") return `<span class="data-source warn">${icon("hard-drive")}离线缓存 · ${htmlEscape(mvpState.lastError)}</span>`;
    return `<span class="data-source warn">${icon("wifi-off")}演示模式 · 启动后端可接入真实扫描</span>`;
  };

  function normalizeFinding(f, idx = 0) {
    const sev = String(f.severity || "").toLowerCase();
    return {
      ...f,
      id: textOr(f.id, `finding-${idx}`),
      vuln_id: textOr(f.vuln_id || f.id, `VUL-${idx + 1}`),
      severity: sev || "info",
      severity_label: f.severity_label || sevLabel(sev),
      cwe: f.cwe || f.cwe_id || f.cwe_description || "CWE-UNKNOWN",
      file: f.rel_path || f.source_file || f.file || "-",
      line: Number(f.line || 0),
      function_name: f.function_name || f.function || "-",
      status: f.status || "待确认",
      source: f.source || "真实报告",
      confidence: f.confidence ?? "-",
      description: f.description || f.location || "",
      suggestion: f.suggestion || "",
      project: f.project || "default",
    };
  }

  realFindings = function productionRealFindings() {
    if (Array.isArray(mvpState.data?.findings)) return mvpState.data.findings.map(normalizeFinding);
    return findings.map((f, idx) =>
      normalizeFinding(
        {
          id: `mock-${idx}`,
          vuln_id: f[0],
          severity_label: f[1],
          severity: f[1] === "高危" || f[1] === "楂樺嵄" ? "high" : f[1] === "中危" || f[1] === "涓嵄" ? "medium" : "low",
          cwe: f[2],
          file: f[3],
          line: f[4],
          function_name: f[5],
          source: f[6],
          status: f[7],
          confidence: f[8],
          description: "演示漏洞详情。启动 Web 后端并运行扫描后，这里会显示 result/ 中的真实报告内容。",
          suggestion: "运行一次扫描或放入真实 *.report.json。",
        },
        idx,
      ),
    );
  };

  realReports = function productionRealReports() {
    if (Array.isArray(mvpState.data?.reports)) return mvpState.data.reports;
    return reports.map((r, idx) => ({
      id: `mock-report-${idx}`,
      file: r[0],
      project: r[2],
      total_vulnerabilities: r[7],
      scan_time: r[8],
      severity_summary: { high: r[4], medium: r[5], low: r[6] },
      path: "演示报告",
    }));
  };

  realJobs = function productionRealJobs() {
    if (Array.isArray(mvpState.data?.scans)) return mvpState.data.scans;
    return tasks.map((t, idx) => ({
      id: t[0],
      status: idx < 2 ? "running" : idx < 4 ? "completed" : "failed",
      command_display: t[1],
      created_at: "2025-06-01 14:32:45",
      started_at: idx < 2 ? "2025-06-01 14:33:02" : "2025-06-01 14:32:58",
      duration_sec: idx < 2 ? 0 : 120 + idx * 30,
      returncode: idx < 4 ? 0 : 1,
      pid: idx < 2 ? 10000 + idx : null,
    }));
  };

  function pageFilter(page) {
    if (!mvpState.filters[page]) mvpState.filters[page] = structuredCloneSafe(DEFAULT_FILTERS[page] || DEFAULT_FILTERS.results);
    return mvpState.filters[page];
  }

  function searchBlob(item, keys) {
    return keys.map((key) => item[key]).join(" ").toLowerCase();
  }

  function statusKey(status) {
    const value = String(status || "").toLowerCase();
    if (value.includes("fail") || value.includes("失败") || value.includes("澶辫触") || value.includes("error")) return "failed";
    if (value.includes("complete") || value.includes("done") || value.includes("已完成") || value.includes("宸插畬")) return "completed";
    if (value.includes("run") || value.includes("运行") || value.includes("杩愯")) return "running";
    if (value.includes("queue") || value.includes("wait") || value.includes("等待") || value.includes("排队")) return "queued";
    if (value.includes("确认") || value.includes("纭")) return "confirmed";
    return value || "unknown";
  }

  function statusLabel(status) {
    return { running: "运行中", completed: "已完成", failed: "失败", queued: "排队中", confirmed: "已确认", unknown: "未知" }[statusKey(status)] || textOr(status);
  }

  function paginate(items, filter) {
    const pageSize = clampNumber(filter.pageSize, 5, 50, 10);
    const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
    const pageNo = clampNumber(filter.pageNo, 1, totalPages, 1);
    filter.pageNo = pageNo;
    filter.pageSize = pageSize;
    const start = (pageNo - 1) * pageSize;
    return { items: items.slice(start, start + pageSize), pageNo, pageSize, totalPages, total: items.length, start };
  }

  function filterFindings() {
    const filter = pageFilter("results");
    const q = filter.q.trim().toLowerCase();
    return realFindings().filter((item) => {
      const severityOk = filter.severity === "all" || item.severity === filter.severity || (filter.severity === "high" && item.severity === "critical");
      const key = statusKey(item.status);
      const statusOk = filter.status === "all" || key === filter.status || (filter.status === "confirmed" && String(item.status || "").includes("确认"));
      const qOk = !q || searchBlob(item, ["vuln_id", "id", "cwe", "file", "function_name", "status", "description", "suggestion", "project"]).includes(q);
      return severityOk && statusOk && qOk;
    });
  }

  function filterJobs() {
    const filter = pageFilter("tasks");
    const q = filter.q.trim().toLowerCase();
    return realJobs().filter((item) => {
      const statusOk = filter.status === "all" || statusKey(item.status) === filter.status;
      const qOk = !q || searchBlob(item, ["id", "pid", "status", "command_display", "created_at", "started_at"]).includes(q);
      return statusOk && qOk;
    });
  }

  function filterReports() {
    const filter = pageFilter("reports");
    const q = filter.q.trim().toLowerCase();
    return realReports().filter((item) => {
      const sev = item.severity_summary || {};
      const severityOk =
        filter.severity === "all" ||
        (filter.severity === "high" && Number(sev.critical || 0) + Number(sev.high || 0) > 0) ||
        (filter.severity !== "high" && Number(sev[filter.severity] || 0) > 0);
      const qOk = !q || searchBlob(item, ["id", "file", "path", "project", "scan_time"]).includes(q);
      return severityOk && qOk;
    });
  }

  function option(value, label, current) {
    return `<option value="${htmlEscape(value)}"${String(current) === String(value) ? " selected" : ""}>${htmlEscape(label)}</option>`;
  }

  function filterBar(page) {
    const filter = pageFilter(page);
    const severity = "severity" in filter;
    const status = "status" in filter;
    const placeholders = {
      results: "搜索漏洞 ID、CWE、文件、函数、描述",
      tasks: "搜索任务 ID、PID、命令、状态",
      reports: "搜索报告、项目、路径、时间",
    };
    return `
      <section class="prod-filter-row" data-filter-page="${page}">
        <label class="search-box prod-search">${icon("search")}<input data-filter="q" value="${htmlEscape(filter.q)}" placeholder="${placeholders[page] || "搜索"}" /></label>
        ${
          severity
            ? `<label class="filter-select"><span>风险</span><select data-filter="severity">
              ${option("all", "全部风险", filter.severity)}
              ${option("critical", "严重", filter.severity)}
              ${option("high", "高危", filter.severity)}
              ${option("medium", "中危", filter.severity)}
              ${option("low", "低危", filter.severity)}
              ${option("info", "提示", filter.severity)}
            </select></label>`
            : ""
        }
        ${
          status
            ? `<label class="filter-select"><span>状态</span><select data-filter="status">
              ${option("all", "全部状态", filter.status)}
              ${option("running", "运行中", filter.status)}
              ${option("queued", "排队中", filter.status)}
              ${option("completed", "已完成", filter.status)}
              ${option("failed", "失败", filter.status)}
              ${option("confirmed", "已确认", filter.status)}
            </select></label>`
            : ""
        }
        <label class="filter-select compact"><span>每页</span><select data-filter="pageSize">
          ${[5, 10, 20, 50].map((n) => option(n, `${n} 条`, filter.pageSize)).join("")}
        </select></label>
        <button class="ghost-btn" data-action="clear-filters" data-filter-page="${page}">${icon("rotate-cw")}重置</button>
      </section>
    `;
  }

  function tablePanel(headers, rows, mobileCards, pageInfo, emptyHtml = "") {
    if (!pageInfo.total) return emptyHtml;
    const from = pageInfo.start + 1;
    const to = Math.min(pageInfo.start + pageInfo.pageSize, pageInfo.total);
    return `
      <section class="panel prod-data-panel">
        <div class="table-shell">
          <table class="data-table">
            <thead><tr>${headers.map((h) => `<th>${htmlEscape(h)}</th>`).join("")}</tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div class="mobile-card-list">${mobileCards}</div>
        <div class="table-footer prod-footer">
          <span>显示 ${from}-${to} / 共 ${pageInfo.total} 条</span>
          <div class="pager">
            <button data-action="page-prev" ${pageInfo.pageNo <= 1 ? "disabled" : ""}>${icon("chevron-left")}</button>
            <button class="is-active" data-action="page-set" data-page-no="${pageInfo.pageNo}">${pageInfo.pageNo}</button>
            <span class="pager-total">/ ${pageInfo.totalPages}</span>
            <button data-action="page-next" ${pageInfo.pageNo >= pageInfo.totalPages ? "disabled" : ""}>${icon("chevron-right")}</button>
          </div>
        </div>
      </section>
    `;
  }

  function jobProgress(job) {
    const key = statusKey(job.status);
    if (key === "completed") return { label: "完成", width: 100, cls: "green" };
    if (key === "failed") return { label: "失败", width: 100, cls: "red" };
    if (key === "running") return { label: "运行中", width: 44, cls: "is-indeterminate" };
    return { label: "等待调度", width: 12, cls: "" };
  }

  mvpResults = function productionResults() {
    const filtered = filterFindings();
    const pageInfo = paginate(filtered, pageFilter("results"));
    const rows = pageInfo.items
      .map((f) => {
        const tone = sevTone(f.severity);
        const confidence = typeof f.confidence === "number" ? `${f.confidence}%` : textOr(f.confidence, "-");
        return `
          <tr>
            <td><button class="row-link" data-action="finding-detail" data-id="${htmlEscape(f.id)}">${htmlEscape(f.vuln_id || f.id)}</button></td>
            <td><span class="badge ${tone}">${htmlEscape(f.severity_label || sevLabel(f.severity))}</span></td>
            <td>${htmlEscape(f.cwe || "-")}</td>
            <td>${htmlEscape(f.file || "-")}</td>
            <td>${htmlEscape(f.line || "-")}</td>
            <td>${htmlEscape(f.function_name || "-")}</td>
            <td><span class="badge ${statusTone(f.status)}">${htmlEscape(f.status || "待确认")}</span></td>
            <td>${htmlEscape(confidence)}</td>
            <td><button class="table-action" data-action="finding-detail" data-id="${htmlEscape(f.id)}" title="查看详情">${icon("eye")}</button><button class="table-action" data-action="finding-evidence" data-id="${htmlEscape(f.id)}" title="证据链">${icon("git-branch")}</button></td>
          </tr>`;
      })
      .join("");
    const cards = pageInfo.items
      .map((f) => `<article class="mobile-data-card" data-action="finding-detail" data-id="${htmlEscape(f.id)}"><div><b>${htmlEscape(f.vuln_id || f.id)}</b><span class="badge ${sevTone(f.severity)}">${htmlEscape(f.severity_label || sevLabel(f.severity))}</span></div><p>${htmlEscape(f.cwe)} · ${htmlEscape(f.file)}:${htmlEscape(f.line || "-")}</p><small>${htmlEscape(f.description || f.status || "")}</small></article>`)
      .join("");
    app.innerHTML = `
      ${pageHead("results", `${dataSourceBadge()}<button class="ghost-btn" data-action="refresh-data">${icon("refresh-cw")}刷新</button><button class="primary-action" data-page="reports">${icon("file-down")}查看报告</button>`)}
      ${mvpStatCards("results")}
      ${filterBar("results")}
      ${
        realFindings().length
          ? `<section class="dashboard-grid"><div>${tablePanel(
              ["漏洞ID", "风险", "CWE", "文件", "行", "函数", "状态", "置信度", "操作"],
              rows,
              cards,
              pageInfo,
              emptyState("没有匹配的漏洞", "调整搜索、风险或状态筛选后再试。", false),
            )}</div><aside class="right-stack"><section class="panel"><div class="panel-title"><h2>漏洞趋势</h2></div>${lineChart()}</section>${mvpDonutPanel("漏洞类型分布")}${mvpDonutPanel("报告来源分布", true)}</aside></section>`
          : emptyState("暂无真实漏洞结果", "运行扫描后，这里会展示真实漏洞列表、置信度、证据链和代码上下文。")
      }
    `;
  };

  mvpTasks = function productionTasks() {
    const filtered = filterJobs();
    const pageInfo = paginate(filtered, pageFilter("tasks"));
    const rows = pageInfo.items
      .map((j) => {
        const progress = jobProgress(j);
        return `
          <tr>
            <td><button class="row-link" data-action="scan-detail" data-id="${htmlEscape(j.id)}">${htmlEscape(j.id)}</button><br><span style="color:var(--muted)">${htmlEscape(j.command_display || "扫描任务")}</span></td>
            <td>${htmlEscape(j.pid || "-")}</td>
            <td>${htmlEscape(j.created_at || "-")}</td>
            <td>${htmlEscape(j.started_at || "-")}</td>
            <td><span class="badge ${statusTone(j.status)}">${htmlEscape(statusLabel(j.status))}</span><div class="progress-cell"><div class="progress ${progress.cls}"><span style="width:${progress.width}%"></span></div><span>${progress.label}</span></div></td>
            <td>${htmlEscape(j.duration_sec || 0)}s</td>
            <td>${htmlEscape(j.returncode ?? "-")}</td>
            <td><button class="table-action" data-action="scan-detail" data-id="${htmlEscape(j.id)}" title="查看任务">${icon("eye")}</button><button class="table-action" data-action="refresh-job" data-id="${htmlEscape(j.id)}" title="刷新日志">${icon("refresh-cw")}</button></td>
          </tr>`;
      })
      .join("");
    const cards = pageInfo.items
      .map((j) => `<article class="mobile-data-card" data-action="scan-detail" data-id="${htmlEscape(j.id)}"><div><b>${htmlEscape(j.id)}</b><span class="badge ${statusTone(j.status)}">${htmlEscape(statusLabel(j.status))}</span></div><p>PID ${htmlEscape(j.pid || "-")} · ${htmlEscape(j.duration_sec || 0)}s</p><small>${htmlEscape(j.command_display || "扫描任务")}</small></article>`)
      .join("");
    app.innerHTML = `
      ${pageHead("tasks", `${dataSourceBadge()}<button class="ghost-btn" data-action="refresh-data">${icon("refresh-cw")}刷新</button><button class="primary-action" data-action="new-scan">${icon("plus")}新建检测任务</button>`)}
      ${mvpStatCards("tasks")}
      ${filterBar("tasks")}
      ${realJobs().length ? tablePanel(["任务ID", "PID", "创建时间", "开始时间", "状态", "耗时", "退出码", "操作"], rows, cards, pageInfo, emptyState("没有匹配的任务", "调整搜索或状态筛选后再试。", false)) : emptyState("暂无 Web 扫描任务", "点击“新建检测任务”即可由后端启动 python main.py 扫描。")}
      <section class="work-grid">
        <section class="panel"><div class="panel-title"><h2>任务执行趋势</h2></div>${lineChart()}</section>
        <section class="panel"><div class="panel-title"><h2>扫描状态占比</h2></div>${mvpDonutPanel("扫描状态占比", true)}</section>
      </section>
    `;
  };

  mvpReports = function productionReports() {
    const filtered = filterReports();
    const pageInfo = paginate(filtered, pageFilter("reports"));
    const rows = pageInfo.items
      .map((r) => {
        const sev = r.severity_summary || {};
        return `<tr>
          <td><button class="row-link" data-action="report-detail" data-id="${htmlEscape(r.id)}">${htmlEscape(r.file || r.path || r.id)}</button><br><span style="color:var(--muted)">报告ID: ${htmlEscape(r.id)} <span class="badge info">JSON</span></span></td>
          <td>${htmlEscape(r.project || "-")}</td><td>检测报告</td><td><span style="color:var(--red)">${Number(sev.critical || 0) + Number(sev.high || 0)}</span></td>
          <td><span style="color:var(--orange)">${Number(sev.medium || 0)}</span></td><td><span style="color:var(--blue-2)">${Number(sev.low || 0)}</span></td>
          <td>${htmlEscape(r.total_vulnerabilities || 0)}</td><td>${htmlEscape(r.scan_time || "-")}</td><td><span class="badge ok">可读取</span></td>
          <td><button class="table-action" data-action="report-detail" data-id="${htmlEscape(r.id)}" title="预览报告">${icon("eye")}</button><button class="table-action" data-action="not-implemented" title="导出">${icon("download")}</button></td>
        </tr>`;
      })
      .join("");
    const cards = pageInfo.items
      .map((r) => `<article class="mobile-data-card" data-action="report-detail" data-id="${htmlEscape(r.id)}"><div><b>${htmlEscape(r.file || r.id)}</b><span class="badge ok">可读取</span></div><p>${htmlEscape(r.project || "-")} · ${htmlEscape(r.total_vulnerabilities || 0)} 个漏洞</p><small>${htmlEscape(r.scan_time || r.path || "")}</small></article>`)
      .join("");
    app.innerHTML = `
      ${pageHead("reports", `${dataSourceBadge()}<button class="ghost-btn" data-action="refresh-data">${icon("refresh-cw")}刷新</button><button class="primary-action" data-action="new-scan">${icon("file-plus")}生成报告</button>`)}
      ${mvpStatCards("reports")}
      ${filterBar("reports")}
      ${
        realReports().length
          ? `<section class="report-layout"><div>${tablePanel(
              ["报告信息", "所属项目", "类型", "高危", "中危", "低危", "总数", "生成时间", "状态", "操作"],
              rows,
              cards,
              pageInfo,
              emptyState("没有匹配的报告", "调整搜索或风险筛选后再试。", false),
            )}</div><aside class="right-stack">${mvpDonutPanel("漏洞等级分布")}<section class="panel"><div class="panel-title"><h2>报告操作</h2></div><div class="drawer-agents"><button class="small-btn" data-action="new-scan">${icon("refresh-cw")}重新生成</button><button class="small-btn" data-action="refresh-data">${icon("database")}重读 result/</button></div></section></aside></section>`
          : emptyState("暂无真实报告", "扫描结束后，后端会从 result/*.report.json 读取报告并在这里展示。")
      }
    `;
  };

  function clearDrawerPoll() {
    if (mvpState.drawerTimer) window.clearTimeout(mvpState.drawerTimer);
    mvpState.drawerTimer = null;
  }

  openDrawerHtml = function productionOpenDrawerHtml(html) {
    const drawer = document.querySelector(".scan-drawer");
    if (!drawer) return;
    drawer.innerHTML = html;
    drawer.setAttribute("aria-hidden", "false");
    drawer.setAttribute("role", "dialog");
    drawer.setAttribute("aria-modal", "true");
    document.body.classList.add("drawer-open");
    refreshIcons();
    window.requestAnimationFrame(() => drawer.querySelector("button, input, select, textarea")?.focus());
  };

  closeDrawer = function productionCloseDrawer({ syncUrl = true } = {}) {
    clearDrawerPoll();
    document.body.classList.remove("drawer-open");
    const drawer = document.querySelector(".scan-drawer");
    drawer?.setAttribute("aria-hidden", "true");
    mvpState.activeDrawer = null;
    if (syncUrl) writeUrlState({ drawer: "", id: "" }, { replace: false });
  };

  openScanDrawer = function productionOpenScanDrawer() {
    mvpState.activeDrawer = { type: "new-scan", id: "new" };
    openDrawerHtml(`
      <div class="drawer-head">
        <div><span class="eyebrow">Backend Scan</span><h2>新建真实扫描任务</h2></div>
        <button class="icon-btn" data-close-drawer aria-label="关闭">${icon("x")}</button>
      </div>
      <div class="form-grid">
        <div class="field field-vertical"><label for="scan-mode">运行模式</label><select id="scan-mode"><option value="scan">工程级扫描 scan</option><option value="detect">单文件/目录检测 detect</option></select></div>
        <div class="field field-vertical"><label for="scan-root">扫描路径 / 文件</label><input id="scan-root" value="dataset/multi_c_project" required /></div>
        <div class="field field-vertical"><label for="scan-parallel">并行度</label><input id="scan-parallel" type="number" min="1" max="16" value="2" /></div>
        <div class="field field-vertical"><label for="scan-max-files">最大文件数</label><input id="scan-max-files" type="number" min="1" placeholder="留空表示不限制" /></div>
        <label class="drawer-section inline-check"><input id="scan-cpg" type="checkbox" /> 启用 workspace CPG</label>
        <div class="drawer-section">
          <h3>执行说明</h3>
          <p class="page-subtitle">后端会运行 <code>python main.py</code>。扫描结果写入 result/，完成后页面会自动刷新真实数据。</p>
        </div>
        <button class="primary-action drawer-submit" data-action="start-scan">${icon("play")}开始检测</button>
      </div>
    `);
  };

  startScanFromDrawer = async function productionStartScanFromDrawer() {
    if (!mvpState.apiOk) {
      toast("当前未连接后端 API，无法启动真实扫描", "error");
      return;
    }
    const mode = document.querySelector("#scan-mode")?.value || "scan";
    const root = (document.querySelector("#scan-root")?.value || "").trim();
    const parallel = clampNumber(document.querySelector("#scan-parallel")?.value, 1, 16, 2);
    const maxFilesRaw = document.querySelector("#scan-max-files")?.value || "";
    if (!root) {
      toast("请填写扫描路径或文件", "error");
      document.querySelector("#scan-root")?.focus();
      return;
    }
    const button = document.querySelector("[data-action='start-scan']");
    button?.setAttribute("disabled", "true");
    const payload = {
      mode,
      parallel,
      max_files: maxFilesRaw ? clampNumber(maxFilesRaw, 1, 100000, 1) : undefined,
      c_workspace_cpg: Boolean(document.querySelector("#scan-cpg")?.checked),
    };
    if (mode === "scan") payload.root = root;
    else {
      payload.source = "local";
      payload.file = root;
    }
    openDrawerHtml(`
      <div class="drawer-head"><div><span class="eyebrow">Starting</span><h2>正在启动扫描</h2></div><button class="icon-btn" data-close-drawer aria-label="关闭">${icon("x")}</button></div>
      <div class="drawer-section"><p class="page-subtitle">后端正在创建子进程，请稍候...</p></div>
    `);
    try {
      const job = await fetchJson("/api/scans", { method: "POST", body: JSON.stringify(payload), timeout: 20000 });
      toast("扫描任务已创建", "success");
      await loadMvpData({ force: true });
      writeUrlState({ page: "tasks", drawer: "scan", id: job.id, pageNo: 1 }, { replace: false });
      await renderPage("tasks");
    } catch (error) {
      toast(error.message || "启动失败", "error");
      openDrawerHtml(`<div class="drawer-head"><div><span class="eyebrow">Error</span><h2>启动失败</h2></div><button class="icon-btn" data-close-drawer aria-label="关闭">${icon("x")}</button></div><div class="drawer-section"><p class="page-subtitle">${htmlEscape(error.message)}</p></div>`);
    }
  };

  function renderJobDrawer(job, id) {
    const progress = jobProgress(job || {});
    openDrawerHtml(`
      <div class="drawer-head"><div><span class="eyebrow">Scan Job</span><h2>任务详情</h2></div><button class="icon-btn" data-close-drawer aria-label="关闭">${icon("x")}</button></div>
      <div class="detail-grid">
        ${[["任务ID", job?.id || id], ["状态", statusLabel(job?.status)], ["PID", job?.pid || "-"], ["退出码", job?.returncode ?? "-"], ["创建时间", job?.created_at || "-"], ["耗时", `${job?.duration_sec || 0}s`]].map(([a, b]) => `<div class="detail-item"><span>${a}</span><b>${htmlEscape(b)}</b></div>`).join("")}
      </div>
      <div class="drawer-section"><h3>实时状态</h3><div class="progress-cell drawer-progress"><div class="progress ${progress.cls}"><span style="width:${progress.width}%"></span></div><span>${progress.label}</span></div></div>
      <div class="drawer-section"><h3>执行命令</h3><div class="log-box">${htmlEscape(job?.command_display || "")}</div></div>
      <div class="drawer-section"><h3>日志尾部</h3><div class="log-box">${htmlEscape(job?.log_tail || "暂无日志")}</div></div>
      <button class="ghost-btn drawer-submit" data-action="refresh-job" data-id="${htmlEscape(id)}">${icon("refresh-cw")}刷新任务</button>
    `);
  }

  openScanDetail = async function productionOpenScanDetail(id, { syncUrl = true } = {}) {
    if (!id) return;
    clearDrawerPoll();
    mvpState.activeDrawer = { type: "scan", id };
    if (syncUrl) writeUrlState({ page: "tasks", drawer: "scan", id }, { replace: false });
    try {
      const job = mvpState.apiOk ? await fetchJson(`/api/scans/${encodeURIComponent(id)}`, { timeout: 10000 }) : realJobs().find((j) => String(j.id) === String(id));
      if (!job) throw new Error("未找到任务");
      renderJobDrawer(job, id);
      const key = statusKey(job.status);
      if (key === "running" || key === "queued") {
        mvpState.drawerTimer = window.setTimeout(() => openScanDetail(id, { syncUrl: false }), 2500);
      } else {
        await loadMvpData({ force: true });
        if (mvpState.currentPage === "tasks") mvpTasks();
      }
    } catch (error) {
      toast(error.message || "读取任务失败", "error");
      openDrawerHtml(`<div class="drawer-head"><div><span class="eyebrow">Error</span><h2>读取任务失败</h2></div><button class="icon-btn" data-close-drawer aria-label="关闭">${icon("x")}</button></div><div class="drawer-section">${htmlEscape(error.message)}</div>`);
    }
  };

  openFindingDetail = async function productionOpenFindingDetail(id, { syncUrl = true } = {}) {
    const finding = realFindings().find((f) => String(f.id) === String(id));
    if (!finding) {
      toast("未找到该漏洞，可能已被筛选或报告已刷新", "error");
      return;
    }
    clearDrawerPoll();
    mvpState.activeDrawer = { type: "finding", id };
    if (syncUrl) writeUrlState({ page: "results", drawer: "finding", id }, { replace: false });
    let context = null;
    if (mvpState.apiOk && finding.file) {
      try {
        context = await fetchJson(`/api/code-context?file=${encodeURIComponent(finding.file)}&line=${encodeURIComponent(finding.line || 1)}&radius=8`, { timeout: 10000 });
      } catch {
        context = null;
      }
    }
    openDrawerHtml(`
      <div class="drawer-head"><div><span class="eyebrow">Finding Detail</span><h2>${htmlEscape(finding.cwe || "漏洞详情")}</h2></div><button class="icon-btn" data-close-drawer aria-label="关闭">${icon("x")}</button></div>
      <div class="detail-grid">
        ${[["风险等级", finding.severity_label || sevLabel(finding.severity)], ["置信度", finding.confidence || "-"], ["文件", finding.file || "-"], ["行号", finding.line || "-"], ["状态", finding.status || "-"], ["报告ID", finding.report_id || "-"]].map(([a, b]) => `<div class="detail-item"><span>${a}</span><b>${htmlEscape(b)}</b></div>`).join("")}
      </div>
      <div class="drawer-section"><h3>漏洞描述</h3><p class="page-subtitle">${htmlEscape(finding.description || "报告中暂无描述")}</p></div>
      <div class="drawer-section"><h3>修复建议</h3><p class="page-subtitle">${htmlEscape(finding.suggestion || "报告中暂无修复建议")}</p></div>
      <div class="drawer-section"><h3>代码上下文</h3><div class="code-context">${
        context?.found
          ? context.lines.map((line) => `<span class="${line.hit ? "hit" : ""}">${String(line.number).padStart(5, " ")}  ${htmlEscape(line.text)}</span>`).join("\n")
          : "未找到本地源码上下文。报告文件名可能不是仓库内相对路径。"
      }</div></div>
    `);
  };

  openReportDetail = async function productionOpenReportDetail(id, { syncUrl = true } = {}) {
    clearDrawerPoll();
    mvpState.activeDrawer = { type: "report", id };
    if (syncUrl) writeUrlState({ page: "reports", drawer: "report", id }, { replace: false });
    try {
      const report = mvpState.apiOk ? await fetchJson(`/api/reports/${encodeURIComponent(id)}`, { timeout: 10000 }) : realReports().find((r) => String(r.id) === String(id));
      if (!report) throw new Error("未找到报告");
      const raw = report.raw || report;
      openDrawerHtml(`
        <div class="drawer-head"><div><span class="eyebrow">Report Preview</span><h2>报告详情</h2></div><button class="icon-btn" data-close-drawer aria-label="关闭">${icon("x")}</button></div>
        <div class="detail-grid">
          ${[["报告ID", report.id], ["项目", report.project || "-"], ["文件", report.file || "-"], ["漏洞数", report.total_vulnerabilities || 0], ["扫描时间", report.scan_time || "-"], ["路径", report.path || "-"]].map(([a, b]) => `<div class="detail-item"><span>${a}</span><b>${htmlEscape(b)}</b></div>`).join("")}
        </div>
        <div class="drawer-section"><h3>CWE 分布</h3><div class="legend">${Object.entries(report.vulnerabilities_by_cwe || {}).map(([k, v]) => `<div class="legend-row"><span class="swatch"></span><span>${htmlEscape(k)}</span><b>${htmlEscape(v)}</b></div>`).join("") || "暂无 CWE 数据"}</div></div>
        <div class="drawer-section"><h3>原始 JSON 预览</h3><div class="log-box">${htmlEscape(JSON.stringify(raw, null, 2).slice(0, 8000))}</div></div>
      `);
    } catch (error) {
      toast(error.message || "读取报告失败", "error");
      openDrawerHtml(`<div class="drawer-head"><div><span class="eyebrow">Error</span><h2>读取报告失败</h2></div><button class="icon-btn" data-close-drawer aria-label="关闭">${icon("x")}</button></div><div class="drawer-section">${htmlEscape(error.message)}</div>`);
    }
  };

  function restoreFilterFocus() {
    const pending = mvpState.pendingFilterFocus;
    if (!pending) return;
    window.requestAnimationFrame(() => {
      const input = document.querySelector(`[data-filter-page="${pending.page}"] [data-filter="${pending.name}"]`);
      if (!input) return;
      input.focus();
      if (typeof input.setSelectionRange === "function") {
        const pos = Math.min(pending.position ?? input.value.length, input.value.length);
        input.setSelectionRange(pos, pos);
      }
    });
  }

  async function openDrawerFromRoute(route) {
    if (!route.drawer || !route.id) return;
    if (route.drawer === "finding") await openFindingDetail(route.id, { syncUrl: false });
    if (route.drawer === "scan") await openScanDetail(route.id, { syncUrl: false });
    if (route.drawer === "report") await openReportDetail(route.id, { syncUrl: false });
  }

  renderPage = async function productionRenderPage(key) {
    const route = applyUrlToState();
    const page = VALID_PAGES.has(key) ? key : route.page;
    mvpState.currentPage = page;
    if (!mvpState.loaded) {
      app.innerHTML = `${pageHead(page)}${emptyState("正在连接后端 API", "如果你是直接打开 HTML，将自动使用离线演示数据。", false)}`;
      refreshIcons();
      await loadMvpData();
    }
    const renderers = {
      overview: mvpOverview,
      results: mvpResults,
      tasks: mvpTasks,
      agents: mvpAgents,
      reports: mvpReports,
    };
    if (MVP_PAGES.has(page)) renderers[page]();
    else (baseRenderers[page] || renderOverview)();
    document.querySelectorAll(".nav-item").forEach((btn) => btn.classList.toggle("is-active", btn.dataset.page === page));
    app.scrollTo({ top: 0, behavior: "auto" });
    refreshIcons();
    restoreFilterFocus();
    const nextRoute = readUrlState();
    if (nextRoute.drawer && nextRoute.id) await openDrawerFromRoute(nextRoute);
  };

  window.addEventListener("popstate", () => {
    const route = readUrlState();
    renderPage(route.page);
  });

  window.addEventListener(
    "click",
    async (event) => {
      const close = event.target.closest?.("[data-close-drawer]");
      if (close) {
        event.preventDefault();
        event.stopPropagation();
        closeDrawer();
        return;
      }

      const pageLink = event.target.closest?.("[data-page]");
      if (pageLink) {
        event.preventDefault();
        event.stopPropagation();
        await navigateToPage(pageLink.dataset.page);
        return;
      }

      const actionTarget = event.target.closest?.("[data-action]");
      const action = actionTarget?.dataset.action;
      if (action && PROD_ACTIONS.has(action)) {
        event.preventDefault();
        event.stopPropagation();
        if (action === "new-scan") openScanDrawer();
        if (action === "start-scan") await startScanFromDrawer();
        if (action === "refresh-data") {
          await loadMvpData({ force: true });
          await renderPage(mvpState.currentPage);
          toast(mvpState.apiOk ? "数据已刷新" : "后端不可用，已切换到缓存/演示数据", mvpState.apiOk ? "success" : "error");
        }
        if (action === "scan-detail" || action === "refresh-job") await openScanDetail(actionTarget.dataset.id);
        if (action === "finding-detail" || action === "finding-evidence") await openFindingDetail(actionTarget.dataset.id);
        if (action === "report-detail") await openReportDetail(actionTarget.dataset.id);
        if (action === "clear-filters") {
          const page = actionTarget.dataset.filterPage || mvpState.currentPage;
          if (DEFAULT_FILTERS[page]) mvpState.filters[page] = structuredCloneSafe(DEFAULT_FILTERS[page]);
          updateRouteFromFilter(page, { replace: true });
          await renderPage(page);
          toast("筛选已重置", "success");
        }
        if (action === "page-prev" || action === "page-next" || action === "page-set") {
          const filter = pageFilter(mvpState.currentPage);
          const delta = action === "page-prev" ? -1 : action === "page-next" ? 1 : 0;
          filter.pageNo = action === "page-set" ? Number(actionTarget.dataset.pageNo || 1) : Number(filter.pageNo || 1) + delta;
          updateRouteFromFilter(mvpState.currentPage, { replace: false });
          await renderPage(mvpState.currentPage);
        }
        if (action === "not-implemented") toast("该功能尚未接入生产接口", "info");
        return;
      }

      const passiveButton = event.target.closest?.("button:not([data-action]):not([data-page]):not([data-close-drawer])");
      if (passiveButton && (passiveButton.closest("#app") || passiveButton.closest(".topbar"))) {
        event.preventDefault();
        event.stopPropagation();
        toast("该功能尚未接入生产接口", "info");
      }
    },
    true,
  );

  document.addEventListener(
    "input",
    (event) => {
      const input = event.target.closest?.("[data-filter]");
      const row = input?.closest("[data-filter-page]");
      if (!input || !row) return;
      const page = row.dataset.filterPage;
      const filter = pageFilter(page);
      filter[input.dataset.filter] = input.value;
      filter.pageNo = 1;
      mvpState.pendingFilterFocus = { page, name: input.dataset.filter, position: input.selectionStart };
      window.clearTimeout(mvpState.filterTimer);
      mvpState.filterTimer = window.setTimeout(async () => {
        updateRouteFromFilter(page, { replace: true });
        await renderPage(page);
      }, 180);
    },
    true,
  );

  document.addEventListener(
    "change",
    async (event) => {
      const input = event.target.closest?.("[data-filter]");
      const row = input?.closest("[data-filter-page]");
      if (!input || !row) return;
      const page = row.dataset.filterPage;
      const filter = pageFilter(page);
      filter[input.dataset.filter] = input.value;
      filter.pageNo = 1;
      updateRouteFromFilter(page, { replace: true });
      await renderPage(page);
    },
    true,
  );

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && document.body.classList.contains("drawer-open")) {
      event.preventDefault();
      closeDrawer();
    }
  });

  function installDragScroll() {
    const selectors = ".content, .table-shell, .scan-drawer";
    let state = null;

    document.addEventListener(
      "pointerdown",
      (event) => {
        if (event.button !== 0 || event.pointerType === "touch") return;
        if (event.target.closest("button, a, input, select, textarea, summary, [role='button']")) return;
        const scroller = event.target.closest(selectors);
        if (!scroller) return;
        const canScroll = scroller.scrollHeight > scroller.clientHeight + 1 || scroller.scrollWidth > scroller.clientWidth + 1;
        if (!canScroll) return;
        state = {
          scroller,
          pointerId: event.pointerId,
          startX: event.clientX,
          startY: event.clientY,
          scrollLeft: scroller.scrollLeft,
          scrollTop: scroller.scrollTop,
          dragging: false,
        };
      },
      true,
    );

    document.addEventListener(
      "pointermove",
      (event) => {
        if (!state || event.pointerId !== state.pointerId) return;
        const dx = event.clientX - state.startX;
        const dy = event.clientY - state.startY;
        if (!state.dragging && Math.hypot(dx, dy) < 4) return;
        state.dragging = true;
        state.scroller.classList.add("is-dragging-scroll");
        state.scroller.scrollLeft = state.scrollLeft - dx;
        state.scroller.scrollTop = state.scrollTop - dy;
        event.preventDefault();
      },
      { capture: true, passive: false },
    );

    function stopDragScroll(event) {
      if (!state || event.pointerId !== state.pointerId) return;
      state.scroller.classList.remove("is-dragging-scroll");
      state = null;
    }

    document.addEventListener("pointerup", stopDragScroll, true);
    document.addEventListener("pointercancel", stopDragScroll, true);
  }

  installDragScroll();
})();
