export interface Env { }

class BadRequestException extends Error {
  status: number;
  statusText: string;
  constructor(reason?: string) {
    super(reason);
    this.status = 400;
    this.statusText = "Bad Request";
  }
}

class CloudflareApiException extends Error {
  status: number;
  statusText: string;
  constructor(reason?: string) {
    super(reason);
    this.status = 500;
    this.statusText = "Internal Server Error";
  }
}

class Cloudflare {
  cloudflareUrl: string;
  token: string;

  constructor(options: { token: string }) {
    this.cloudflareUrl = "https://api.cloudflare.com/client/v4";
    this.token = options.token;
  }

  /**
   * Refer to https://developers.cloudflare.com/api/operations/zones-get
   * @param name Domain name to search
   * @returns First result from zones query
   */
  async findZone(name: string) {
    const response = await this._fetchWithToken(`zones?name=${name}`);
    const body: any = await response.json();
    if (!body.success || body.result.length === 0) {
      throw new CloudflareApiException(`Failed to find zone '${name}'`);
    }
    return body.result[0];
  }

  /**
   * Refer to https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-list-dns-records
   * @param zone Zone object from zones-get endpoint
   * @param name DNS record name (or @ for apex) in Punycode
   * @returns First result from DNS records query
   */
  async findRecord(zone: any, name: string) {
    const response = await this._fetchWithToken(`zones/${zone.id}/dns_records?name=${name}`);
    const body: any = await response.json();
    if (!body.success || body.result.length === 0) {
      throw new CloudflareApiException(`Failed to find dns record '${name}'`);
    }
    return body.result[0];
  }

  /**
   * Refer to https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-update-dns-record
   * @param record DNS record object from DNS records query
   * @param value IPv4 address for DNS record (A)
   * @returns Result from update DNS Record response
   */
  async updateRecord(record: any, value: string) {
    record.content = value;
    const response = await this._fetchWithToken(
      `zones/${record.zone_id}/dns_records/${record.id}`,
      {
        method: "PUT",
        body: JSON.stringify(record),
      }
    );
    const body: any = await response.json();
    if (!body.success) {
      throw new CloudflareApiException("Failed to update dns record");
    }
    return body.result;
  }

  async _fetchWithToken(endpoint: string, options: RequestInit<RequestInitCfProperties> = {}) {
    const url = `${this.cloudflareUrl}/${endpoint}`;
    options.headers = {
      ...options.headers,
      "Content-Type": "application/json",
      Authorization: `Bearer ${this.token}`,
    };
    return fetch(url, options);
  }
}

function parseBasicAuth(request: Request) {
  const authorization = request.headers.get("Authorization");
  if (!authorization) {
    throw new BadRequestException("Please provide valid credentials");
  }

  const [scheme, data] = authorization.split(" ");
  if (!/^Basic$/i.test(scheme)) {
    throw new BadRequestException("Invalid authorization scheme")
  }

  const decoded = atob(data);
  const index = decoded.indexOf(":");

  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
    throw new BadRequestException("Invalid authorization value");
  }

  return {
    username: decoded.substring(0, index),
    password: decoded.substring(index + 1),
  };
}

async function informAPI(url: URL, name: string, token: string) {
  const hostnames = (url.searchParams.get("hostname") || "").split(",");
  const ip = url.searchParams.get("ip") || url.searchParams.get("myip") || "";

  const cloudflare = new Cloudflare({ token });

  const zone = await cloudflare.findZone(name);
  for (const hostname of hostnames) {
    const record = await cloudflare.findRecord(zone, hostname);
    await cloudflare.updateRecord(record, ip);
  }

  return new Response("good", {
    status: 200,
    headers: {
      "Content-Type": "text/plain;charset=UTF-8",
      "Cache-Control": "no-store",
    },
  });
}

async function handleRequest(request: Request) {
  const url = new URL(request.url);
  const { protocol, pathname, searchParams } = url;

  const forwardedProtocol = request.headers.get("x-forwarded-proto");
  if (protocol !== "https:" || forwardedProtocol !== "https") {
    throw new BadRequestException("Please use a HTTPS connection");
  }

  if (pathname === "/favicon.ico" || pathname === "/robots.txt") {
    return new Response(null, { status: 204 });
  }

  if (pathname !== "/nic/update" && pathname !== "/update") {
    return new Response("Not Found", { status: 404 });
  }

  if (!searchParams) {
    throw new BadRequestException("You must include proper query parameters");
  }

  if (!searchParams.get("hostname")) {
    throw new BadRequestException("You must specify a hostname");
  }

  if (!(searchParams.get("ip") || searchParams.get("myip"))) {
    throw new BadRequestException("You must specify an ip address");
  }

  const { username, password } = parseBasicAuth(request);
  return informAPI(url, username, password);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    return handleRequest(request).catch((err) => {
      console.error(err.constructor.name, err);
      const message = err.reason || err.stack || "Unknown Error";

      return new Response(message, {
        status: err.status || 500,
        statusText: err.statusText || null,
        headers: {
          "Content-Type": "text/plain;charset=UTF-8",
          "Cache-Control": "no-store",
          "Content-Length": message.length,
        },
      });
    });
  },
};
