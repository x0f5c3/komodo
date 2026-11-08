import { useFullCertificate } from ".";
import { usePermissions, useRead, useWrite } from "@/lib/hooks";
import { Config, ConfigItem, ConfigList, MonacoEditor } from "mogh_ui";
import { Button, Group, Select, Stack } from "@mantine/core";
import { useLocalStorage } from "@mantine/hooks";
import { Types } from "komodo_client";
import ResourceSelector from "@/resources/selector";
import { useState } from "react";

export default function CertificateConfig({ id }: { id: string }) {
  const certificate = useFullCertificate(id);
  const { canWrite } = usePermissions({ type: "Certificate", id });
  const disabled =
    !canWrite || (useRead("GetCoreInfo", {}).data?.ui_write_disabled ?? false);
  const { mutateAsync } = useWrite("UpdateCertificate");
  const [update, setUpdate] =
    useLocalStorage<Partial<Types.CertificateConfig>>({
      key: `certificate-${id}-update-v1`,
      defaultValue: {},
    });
  const [routeJson, setRouteJson] = useState<string | undefined>();
  const config = certificate?.config;
  if (!config) return null;

  return (
    <Config
      disabled={disabled}
      original={config}
      update={update}
      setUpdate={setUpdate}
      onSave={() => mutateAsync({ id, config: update })}
      groups={{
        "": [
          {
            label: "Issuance",
            fields: {
              server_id: (server, set) => (
                <ConfigItem label="Unix Periphery host">
                  <ResourceSelector
                    type="Server"
                    selected={server}
                    onSelect={(server_id) => set({ server_id })}
                    disabled={disabled}
                  />
                </ConfigItem>
              ),
              domains: (domains, set) => (
                <ConfigList
                  label="DNS names"
                  description="Wildcard names may be issued with Cloudflare DNS-01; proxy routes must be exact hostnames."
                  field="domains"
                  values={domains ?? []}
                  set={set}
                  disabled={disabled}
                  placeholder="example.com"
                />
              ),
              provider: (provider, set) => (
                <Select
                  label="Provider"
                  value={provider}
                  onChange={(value) =>
                    value &&
                    set({ provider: value as Types.CertificateProvider })
                  }
                  disabled={disabled}
                  data={[
                    { value: Types.CertificateProvider.CloudflareDns01, label: "Cloudflare DNS-01 (Certbot)" },
                    { value: Types.CertificateProvider.Tailscale, label: "Tailscale cert" },
                  ]}
                />
              ),
              email:
                (update.provider ?? config.provider) ===
                  Types.CertificateProvider.CloudflareDns01 && {
                  description: "ACME account contact email.",
                  placeholder: "admin@example.com",
                },
              cloudflare_token_secret:
                (update.provider ?? config.provider) ===
                  Types.CertificateProvider.CloudflareDns01 && {
                  description:
                    "Periphery-local secret key name. The token value is never stored in Core or returned by the API.",
                },
              tailscale_cert_name:
                (update.provider ?? config.provider) ===
                  Types.CertificateProvider.Tailscale && {
                  description:
                    "Optional DNS name passed to the host's authenticated Tailscale CLI.",
                },
            },
          },
          {
            label: "Proxy routes",
            description:
              "Exact-domain routes use the managed Pingora proxy on HTTPS port 443. Do not include wildcard domains.",
            fields: {
              proxy_routes: (routes, set) => {
                const current = routeJson ?? JSON.stringify(routes ?? [], null, 2);
                return (
                  <Stack>
                    <MonacoEditor
                      value={current}
                      language="json"
                      readOnly={disabled}
                      onValueChange={(value) => {
                        setRouteJson(value);
                        try {
                          const parsed = JSON.parse(value);
                          if (Array.isArray(parsed)) set({ proxy_routes: parsed });
                        } catch {
                          // Keep the editor text local until it is valid JSON.
                        }
                      }}
                    />
                    <Group>
                      <Button
                        variant="light"
                        disabled={disabled}
                        onClick={() => {
                          const next = [
                            ...(routes ?? []),
                            {
                              domain: "",
                              upstream: "http://127.0.0.1:8080",
                              tls_mode: Types.CertificateTlsMode.Terminate,
                              redirect_http_to_https: true,
                            },
                          ];
                          set({ proxy_routes: next });
                          setRouteJson(JSON.stringify(next, null, 2));
                        }}
                      >
                        Add route
                      </Button>
                    </Group>
                  </Stack>
                );
              },
            },
          },
        ],
      }}
    />
  );
}
