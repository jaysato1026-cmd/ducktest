export async function runAutomaticSequence({
  initialConfig,
  options,
  executeRound,
  getNextConfig,
  isCancelled = () => false,
  onRoundStart = () => {},
  onRoundComplete = () => {},
  onWaiting = () => {},
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  const totalRounds = options.enabled ? options.maxRounds : 1;
  const reports = [];
  let currentConfig = initialConfig;

  for (let round = 1; round <= totalRounds && !isCancelled(); round += 1) {
    onRoundStart({ config: currentConfig, round, totalRounds });
    const result = await executeRound(currentConfig);
    reports.push(result);
    onRoundComplete({ config: currentConfig, result, reports: [...reports], round, totalRounds });
    if (!options.enabled || round >= totalRounds || result.stopped || isCancelled()) break;
    currentConfig = getNextConfig(result, currentConfig);
    for (let remaining = options.cooldownSeconds; remaining > 0 && !isCancelled(); remaining -= 1) {
      onWaiting({ config: currentConfig, round, totalRounds, remaining });
      await sleep(1000);
    }
  }

  return {
    reports,
    finalConfig: currentConfig,
    stopped: isCancelled(),
    completedRounds: reports.length,
    totalRounds,
  };
}
