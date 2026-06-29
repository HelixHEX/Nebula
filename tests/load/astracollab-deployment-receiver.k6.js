import crypto from "k6/crypto";
import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  scenarios: {
    receiver_replay_and_rejects: {
      executor: "constant-vus",
      vus: Number(__ENV.ASTRACOLLAB_RECEIVER_VUS || 10),
      duration: __ENV.ASTRACOLLAB_RECEIVER_DURATION || "1m",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.02"],
    http_req_duration: ["p(95)<500"],
  },
};

const baseUrl = __ENV.ASTRACOLLAB_URL || "http://127.0.0.1:3000";
const secret = __ENV.NEBULA_DEPLOY_WEBHOOK_SIGNING_SECRET || "dev-secret";
const endpointSecret = __ENV.ASTRACOLLAB_DEPLOYMENT_SECRET || "manual-secret-for-load";
const endpointHeader = __ENV.ASTRACOLLAB_DEPLOYMENT_SECRET_HEADER || "x-astracollab-deployment-secret";

export default function () {
  const sentAt = Date.now();
  const requestId = `load-${__VU}-${__ITER}`;
  const body = JSON.stringify({
    request_id: requestId,
    repository_id: "repo_load",
    projection_id: "proj_load",
    environment_id: "env_prod",
    requested_provider_key: "manual",
    requested_by: "load-test",
    trigger_source: "k6",
    handoff: { sent_at_unix_ms: sentAt },
  });
  const signature = `sha256:${crypto.sha256(`${secret}:${requestId}:${sentAt}:${body}`, "hex")}`;

  const response = http.post(`${baseUrl}/api/webhook/deployments`, body, {
    headers: {
      "content-type": "application/json",
      "x-nebula-request-id": requestId,
      "x-nebula-sent-at": String(sentAt),
      "x-nebula-signature": signature,
      [endpointHeader]: endpointSecret,
    },
  });

  check(response, {
    "receiver accepted or auth rejected predictably": (res) =>
      [200, 401, 501].includes(res.status),
  });
  sleep(0.2);
}
