import { useRead } from "@/lib/hooks";
import { Types } from "komodo_client";
import {
  ActionIcon,
  Button,
  Group,
  NumberInput,
  Select,
  Stack,
  Switch,
  Text,
  TextInput,
} from "@mantine/core";
import { ICONS } from "@/lib/icons";

type Props = {
  serverId: string;
  config: Types.ReverseProxyConfig;
  onChange: (config: Types.ReverseProxyConfig) => void;
  disabled: boolean;
};

const EMPTY_PROXY: Types.ReverseProxyConfig = {
  enabled: false,
  http_port: 80,
  https_port: 443,
  routes: [],
};

export default function ReverseProxyConfigEditor({
  serverId,
  config,
  onChange,
  disabled,
}: Props) {
  const certificates = useRead(
    "ListCertificates",
    { query: {}, limit: 0 },
    { enabled: !!serverId },
  ).data ?? [];
  const certificateOptions = certificates
    .filter(
      (certificate) =>
        certificate.info.server_id === serverId &&
        certificate.info.status === Types.CertificateStatus.Ready,
    )
    .map((certificate) => ({
      value: certificate.id,
      label: `${certificate.name} (${certificate.info.domains.join(", ")})`,
    }));

  const updateRoute = (
    index: number,
    update: Partial<Types.ReverseProxyRoute>,
  ) => {
    const routes = config.routes ?? [];
    onChange({
      ...config,
      routes: routes.map((route, i) =>
        i === index ? { ...route, ...update } : route,
      ),
    });
  };

  const routes = config.routes ?? [];
  return (
    <Stack>
      <Switch
        label="Enable managed reverse proxy"
        description="Komodo runs a dedicated Pingora container on this Server and keeps its routes in sync."
        checked={config.enabled ?? false}
        onChange={(event) =>
          onChange({ ...config, enabled: event.currentTarget.checked })
        }
        disabled={disabled}
      />
      {config.enabled && (
        <>
          <Group grow>
            <NumberInput
              label="HTTP host port"
              min={1}
              max={65535}
              value={config.http_port}
              onChange={(value) =>
                onChange({
                  ...config,
                  http_port:
                    typeof value === "number" ? value : config.http_port,
                })
              }
              disabled={disabled}
            />
            <NumberInput
              label="HTTPS host port"
              min={1}
              max={65535}
              value={config.https_port}
              onChange={(value) =>
                onChange({
                  ...config,
                  https_port:
                    typeof value === "number" ? value : config.https_port,
                })
              }
              disabled={disabled}
            />
          </Group>
          <Text size="sm" c="dimmed">
            Ports must be free on the host. Upstreams must be reachable from
            the proxy container; use host.docker.internal for services
            published on this host.
          </Text>
          {routes.map((route, index) => {
            const terminated = route.tls.type === "terminate";
            return (
              <Group key={index} align="end" wrap="nowrap">
                <TextInput
                  label="Domain"
                  placeholder="app.example.com"
                  value={route.domain}
                  onChange={(event) =>
                    updateRoute(index, {
                      domain: event.currentTarget.value,
                    })
                  }
                  required
                  disabled={disabled}
                  style={{ flex: 1 }}
                />
                <TextInput
                  label={terminated ? "HTTP(S) upstream URL" : "TLS upstream"}
                  placeholder={
                    terminated
                      ? "http://host.docker.internal:3000"
                      : "host.docker.internal:8443"
                  }
                  value={route.upstream}
                  onChange={(event) =>
                    updateRoute(index, {
                      upstream: event.currentTarget.value,
                    })
                  }
                  required
                  disabled={disabled}
                  style={{ flex: 1 }}
                />
                <Select
                  label="TLS mode"
                  data={[
                    { value: "terminate", label: "Terminate" },
                    { value: "passthrough", label: "Passthrough" },
                  ]}
                  value={route.tls.type}
                  onChange={(type) => {
                    if (type === "passthrough") {
                      updateRoute(index, {
                        tls: { type: "passthrough" },
                      });
                    } else if (type === "terminate") {
                      updateRoute(index, {
                        tls: {
                          type: "terminate",
                          params: {
                            certificate_id:
                              route.tls.type === "terminate"
                                ? route.tls.params.certificate_id
                                : "",
                          },
                        },
                      });
                    }
                  }}
                  disabled={disabled}
                  w={150}
                />
                {terminated && route.tls.type === "terminate" && (
                  <Select
                    label="Certificate"
                    data={certificateOptions}
                    value={route.tls.params.certificate_id}
                    onChange={(certificate_id) =>
                      updateRoute(index, {
                        tls: {
                          type: "terminate",
                          params: { certificate_id: certificate_id ?? "" },
                        },
                      })
                    }
                    searchable
                    required
                    disabled={disabled}
                    style={{ flex: 1 }}
                  />
                )}
                <ActionIcon
                  aria-label="Remove proxy route"
                  color="red"
                  variant="subtle"
                  disabled={disabled}
                  onClick={() =>
                    onChange({
                      ...config,
                      routes: routes.filter((_, i) => i !== index),
                    })
                  }
                >
                  <ICONS.Delete size="1rem" />
                </ActionIcon>
              </Group>
            );
          })}
          <Button
            leftSection={<ICONS.Add size="1rem" />}
            variant="light"
            w="fit-content"
            disabled={disabled}
            onClick={() =>
              onChange({
                ...config,
                routes: [
                  ...routes,
                  {
                    domain: "",
                    upstream: "",
                    tls: {
                      type: "terminate",
                      params: { certificate_id: "" },
                    },
                  },
                ],
              })
            }
          >
            Add route
          </Button>
        </>
      )}
    </Stack>
  );
}

export function getReverseProxyConfig(
  config?: Types.ReverseProxyConfig,
): Types.ReverseProxyConfig {
  return {
    ...EMPTY_PROXY,
    ...config,
    enabled: config?.enabled ?? false,
    routes: config?.routes ?? [],
  };
}
