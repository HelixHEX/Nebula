import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  scenarios: {
    cas_and_sync_smoke: {
      executor: "constant-vus",
      vus: Number(__ENV.NEBULA_LOAD_VUS || 20),
      duration: __ENV.NEBULA_LOAD_DURATION || "1m",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<750"],
  },
};

const baseUrl = __ENV.NEBULA_REGISTRY_URL || "http://127.0.0.1:3000";
const repositoryId = __ENV.NEBULA_REPOSITORY_ID || "repo_load";
const token = __ENV.NEBULA_TOKEN || "";

const headers = {
  "content-type": "application/json",
  ...(token ? { authorization: `Bearer ${token}` } : {}),
};

export default function () {
  const response = http.get(`${baseUrl}/v1/repositories/${repositoryId}/sync-bundle`, {
    headers,
  });
  check(response, {
    "sync-bundle is not 5xx": (res) => res.status < 500,
  });
  sleep(0.2);
}
