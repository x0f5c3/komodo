import { useRead } from "@/lib/hooks";
import { Types } from "komodo_client";
import { ActionIcon, Button, Group, Select, Stack, TextInput } from "@mantine/core";
import { ConfigItem } from "mogh_ui";
import { ICONS } from "@/lib/icons";

export default function CertificateMounts({
  serverId,
  mounts,
  onChange,
  disabled,
  services,
  requireService = false,
}: {
  serverId: string;
  mounts: Types.CertificateMount[];
  onChange: (mounts: Types.CertificateMount[]) => void;
  disabled: boolean;
  services?: string[];
  requireService?: boolean;
}) {
  const certificates =
    useRead("ListCertificates", {
      query: {
        specific: { server_ids: serverId ? [serverId] : [] },
      },
      limit: 0,
    }).data ?? [];
  const options = certificates.map((certificate) => ({
    value: certificate.id,
    label: `${certificate.name} (${certificate.info.domains.join(", ")})`,
  }));

  return (
    <ConfigItem
      label="Managed Certificates"
      description="Mount host-managed certificate directories read-only. Workload services restart after renewal."
    >
      <Stack>
        {mounts.map((mount, index) => (
          <Group key={`${mount.certificate}-${index}`} align="end" wrap="nowrap">
            <Select
              label="Certificate"
              placeholder="Select Certificate"
              data={options}
              value={mount.certificate}
              onChange={(certificate) =>
                onChange(
                  mounts.map((item, i) =>
                    i === index ? { ...item, certificate: certificate ?? "" } : item,
                  ),
                )
              }
              searchable
              disabled={disabled || !serverId}
              style={{ flex: 2 }}
            />
            <TextInput
              label="Container path"
              placeholder="/run/certs/site"
              value={mount.mount_path}
              onChange={(event) =>
                onChange(
                  mounts.map((item, i) =>
                    i === index
                      ? { ...item, mount_path: event.currentTarget.value }
                      : item,
                  ),
                )
              }
              disabled={disabled}
              style={{ flex: 2 }}
            />
            {requireService && (
              services?.length ? (
                <Select
                  label="Compose service"
                  placeholder="Select service"
                  data={services}
                  value={mount.service}
                  onChange={(service) =>
                    onChange(
                      mounts.map((item, i) =>
                        i === index ? { ...item, service: service ?? "" } : item,
                      ),
                    )
                  }
                  searchable
                  disabled={disabled}
                  style={{ flex: 1 }}
                />
              ) : (
                <TextInput
                  label="Compose service"
                  placeholder="web"
                  value={mount.service}
                  onChange={(event) =>
                    onChange(
                      mounts.map((item, i) =>
                        i === index
                          ? { ...item, service: event.currentTarget.value }
                          : item,
                      ),
                    )
                  }
                  disabled={disabled}
                  style={{ flex: 1 }}
                />
              )
            )}
            <ActionIcon
              color="red"
              variant="subtle"
              disabled={disabled}
              onClick={() =>
                onChange(mounts.filter((_, mountIndex) => mountIndex !== index))
              }
            >
              <ICONS.Delete size="1rem" />
            </ActionIcon>
          </Group>
        ))}
        <Button
          variant="light"
          leftSection={<ICONS.Add size="1rem" />}
          disabled={disabled || !serverId || options.length === 0}
          onClick={() =>
            onChange([
              ...mounts,
              {
                certificate: "",
                mount_path: "",
                service: "",
              },
            ])
          }
        >
          Add Certificate
        </Button>
      </Stack>
    </ConfigItem>
  );
}
