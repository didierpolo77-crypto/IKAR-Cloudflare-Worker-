import { send } from "../lib/ikar.js";

export default function handler(req, res) {
  if (req.method !== "GET") return send(res, 405, { error: "method_not_allowed" });
  return send(res, 200, {
    service: "IKAR Assistant API",
    status: "online",
    provider: "huggingface-inference-providers",
    authentication_configured: Boolean(process.env.IKAR_API_TOKEN),
    model_configured: Boolean(process.env.HF_MODEL || "deepseek-ai/DeepSeek-V4.1-Flash:cheapest"),
    hf_token_configured: Boolean(process.env.HF_TOKEN),
    urlhaus_configured: Boolean(process.env.URLHAUS_AUTH_KEY)
  });
}
