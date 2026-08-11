const os = require("node:os");
const fs = require("node:fs");

function cpuPercent(previous, current) {
  if (!previous || !current) return 0;
  const idle = current.idle - previous.idle;
  const total = current.total - previous.total;
  return total > 0 ? Number(Math.max(0, Math.min(100, (1 - idle / total) * 100)).toFixed(1)) : 0;
}

function cpuSnapshot() {
  return os.cpus().reduce((sum, cpu) => {
    const times = cpu.times;
    return { idle: sum.idle + times.idle, total: sum.total + times.user + times.nice + times.sys + times.irq + times.idle };
  }, { idle: 0, total: 0 });
}

function createSystemMonitor() {
  let previous = cpuSnapshot();
  return () => {
    const current = cpuSnapshot();
    let disk = {};
    try {
      const stat = fs.statfsSync(process.cwd());
      const total = stat.blocks * stat.bsize;
      const free = stat.bavail * stat.bsize;
      disk = { diskFreeBytes: free, diskTotalBytes: total, diskPercent: total ? Number(((1 - free / total) * 100).toFixed(1)) : null };
    } catch { disk = { diskFreeBytes: null, diskTotalBytes: null, diskPercent: null }; }
    const sample = {
      checkedAt: new Date().toISOString(),
      cpuPercent: cpuPercent(previous, current),
      memoryPercent: Number(((1 - os.freemem() / os.totalmem()) * 100).toFixed(1)),
      memoryUsedBytes: os.totalmem() - os.freemem(),
      memoryTotalBytes: os.totalmem(),
      processMemoryBytes: process.memoryUsage().rss,
      processRssBytes: process.memoryUsage().rss,
      loadAverage: os.loadavg(),
      hostname: os.hostname(),
      platform: `${process.platform} ${process.arch}`,
      ...disk,
    };
    previous = current;
    return sample;
  };
}

module.exports = { cpuPercent, createSystemMonitor };
