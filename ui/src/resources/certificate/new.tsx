import NewResource from "@/resources/new";
import { useRead } from "@/lib/hooks";
import { Types } from "komodo_client";
import { Select, Stack, TextInput, Textarea } from "@mantine/core";
import { useState } from "react";

export default function NewCertificate() {
  const servers = useRead("ListServers", {}).data ?? [];
  const [server, setServer] = useState<string | null>(null);
  const [provider, setProvider] = useState<string>(
    Types.CertificateProvider.CloudflareDns01,
  );
  const [domains, setDomains] = useState("");
  const [email, setEmail] = useState("");
  const [tokenSecret, setTokenSecret] = useState("");

  return (
    <NewResource<Types.CertificateConfig>
      type="Certificate"
      readableType="Certificate"
      config={() => ({
        server_id: server ?? "",
        provider: provider as Types.CertificateProvider,
        domains: domains
          .split(/[\n,]/)
          .map((domain) => domain.trim())
          .filter(Boolean),
        email,
        cloudflare_token_secret: tokenSecret,
      })}
      extraInputs={
        <Stack>
          <Select
            label="Periphery Server"
            placeholder="Select Unix Server"
            value={server}
            onChange={setServer}
            data={servers.map((item) => ({ value: item.id, label: item.name }))}
            searchable
            required
          />
          <Textarea
            label="DNS names"
            description="One hostname per line or comma-separated. Wildcards are supported by Cloudflare DNS-01."
            value={domains}
            onChange={(event) => setDomains(event.currentTarget.value)}
            required
            minRows={2}
          />
          <Select
            label="Provider"
            value={provider}
            onChange={(value) => value && setProvider(value)}
            data={[
              { value: Types.CertificateProvider.CloudflareDns01, label: "Cloudflare DNS-01 (Certbot)" },
              { value: Types.CertificateProvider.Tailscale, label: "Tailscale cert" },
            ]}
          />
          {provider === Types.CertificateProvider.CloudflareDns01 && (
            <>
              <TextInput
                label="ACME email"
                value={email}
                onChange={(event) => setEmail(event.currentTarget.value)}
                required
              />
              <TextInput
                label="Periphery token secret name"
                description="Name of a Periphery-local secret. The token value is never sent to Core."
                value={tokenSecret}
                onChange={(event) => setTokenSecret(event.currentTarget.value)}
                required
              />
            </>
          )}
        </Stack>
      }
    />
  );
}
