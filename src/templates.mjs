export const TEST_TEMPLATES = Object.freeze({
  health: { label: "健康檢查（低負載）", method: "GET", mode: "ramp", concurrency: 5, duration: 30, ramp: 5, timeout: 5000 },
  api: { label: "API 回歸（中負載）", method: "GET", mode: "ramp", concurrency: 20, duration: 60, ramp: 10, timeout: 5000 },
  spike: { label: "尖峰壓力（短時間）", method: "GET", mode: "spike", concurrency: 100, duration: 30, ramp: 0, timeout: 3000 },
  post: { label: "POST 交易流程", method: "POST", mode: "ramp", concurrency: 10, duration: 30, ramp: 5, timeout: 5000, headers: "{\n  \"Content-Type\": \"application/json\"\n}", body: "{\"scenario\":\"smoke\"}" },
});

export function getTemplate(id) { return TEST_TEMPLATES[id] || TEST_TEMPLATES.health; }
