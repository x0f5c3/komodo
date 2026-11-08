import { useRead } from "@/lib/hooks";
import {
  ActionIcon,
  Button,
  Group,
  Select,
  Stack,
  TextInput,
} from "@mantine/core";
import { ICONS } from "@/lib/icons";
import { Types } from "komodo_client";

function useCertificateOptions(serverId: string) {
  const certificates =
    useRead("ListCertificates", { query: {}, limit: 0 }).data ?? [];
  return certificates
    .filter(
      (certificate) =>
        certificate.info.server_id === serverId &&
        certificate.info.status === Types.CertificateStatus.Ready,
    )
    .map((certificate) => ({
      value: certificate.id,
      label: `${certificate.name} (${certificate.info.domains.join(", ")})`,
    }));
}

function refreshOptions() {
  return [
    { value: Types.CertificateRefreshBehavior.Restart, label: "Restart" },
    {
      value: Types.CertificateRefreshBehavior.HotReload,
      label: "Hot reload",
    },
  ];
}

export function DeploymentCertificateAttachments({
  serverId,
  attachments,
  onChange,
  disabled,
}: {
  serverId: string;
  attachments: Types.DeploymentCertificateAttachment[];
  onChange: (attachments: Types.DeploymentCertificateAttachment[]) => void;
  disabled: boolean;
}) {
  const certificateOptions = useCertificateOptions(serverId);
  return (
    <Stack gap="xs">
      {attachments.map((attachment, index) => (
        <Group key={index} align="end" wrap="nowrap">
          <Select
            label="Certificate"
            data={certificateOptions}
            value={attachment.certificate_id}
            onChange={(certificate_id) =>
              onChange(
                attachments.map((current, i) =>
                  i === index
                    ? { ...current, certificate_id: certificate_id ?? "" }
                    : current,
                ),
              )
            }
            searchable
            required
            disabled={disabled}
            style={{ flex: 2 }}
          />
          <TextInput
            label="Container directory"
            placeholder="/run/secrets/tls"
            value={attachment.mount_path}
            onChange={(event) =>
              onChange(
                attachments.map((current, i) =>
                  i === index
                    ? { ...current, mount_path: event.currentTarget.value }
                    : current,
                ),
              )
            }
            required
            disabled={disabled}
            style={{ flex: 2 }}
          />
          <Select
            label="On certificate rotation"
            data={refreshOptions()}
            value={
              attachment.refresh ??
              Types.CertificateRefreshBehavior.Restart
            }
            onChange={(refresh) =>
              onChange(
                attachments.map((current, i) =>
                  i === index
                    ? {
                        ...current,
                        refresh:
                          (refresh as Types.CertificateRefreshBehavior) ??
                          Types.CertificateRefreshBehavior.Restart,
                      }
                    : current,
                ),
              )
            }
            disabled={disabled}
            w={150}
          />
          <ActionIcon
            aria-label="Remove certificate attachment"
            color="red"
            variant="subtle"
            disabled={disabled}
            onClick={() =>
              onChange(attachments.filter((_, i) => i !== index))
            }
          >
            <ICONS.Delete size="1rem" />
          </ActionIcon>
        </Group>
      ))}
      <Button
        leftSection={<ICONS.Add size="1rem" />}
        variant="light"
        w="fit-content"
        disabled={disabled || certificateOptions.length === 0}
        onClick={() =>
          onChange([
            ...attachments,
            {
              certificate_id: "",
              mount_path: "/run/secrets/tls",
              refresh: Types.CertificateRefreshBehavior.Restart,
            },
          ])
        }
      >
        Attach certificate
      </Button>
    </Stack>
  );
}

export function StackCertificateAttachments({
  serverId,
  attachments,
  onChange,
  disabled,
}: {
  serverId: string;
  attachments: Types.StackCertificateAttachment[];
  onChange: (attachments: Types.StackCertificateAttachment[]) => void;
  disabled: boolean;
}) {
  const certificateOptions = useCertificateOptions(serverId);
  return (
    <Stack gap="xs">
      {attachments.map((attachment, index) => (
        <Group key={index} align="end" wrap="nowrap">
          <Select
            label="Certificate"
            data={certificateOptions}
            value={attachment.certificate_id}
            onChange={(certificate_id) =>
              onChange(
                attachments.map((current, i) =>
                  i === index
                    ? { ...current, certificate_id: certificate_id ?? "" }
                    : current,
                ),
              )
            }
            searchable
            required
            disabled={disabled}
            style={{ flex: 2 }}
          />
          <TextInput
            label="Compose service"
            value={attachment.service}
            onChange={(event) =>
              onChange(
                attachments.map((current, i) =>
                  i === index
                    ? {
                        ...current,
                        service: event.currentTarget.value,
                      }
                    : current,
                ),
              )
            }
            required
            disabled={disabled}
            style={{ flex: 1 }}
          />
          <TextInput
            label="Container directory"
            placeholder="/run/secrets/tls"
            value={attachment.mount_path}
            onChange={(event) =>
              onChange(
                attachments.map((current, i) =>
                  i === index
                    ? { ...current, mount_path: event.currentTarget.value }
                    : current,
                ),
              )
            }
            required
            disabled={disabled}
            style={{ flex: 2 }}
          />
          <Select
            label="On certificate rotation"
            data={refreshOptions()}
            value={
              attachment.refresh ??
              Types.CertificateRefreshBehavior.Restart
            }
            onChange={(refresh) =>
              onChange(
                attachments.map((current, i) =>
                  i === index
                    ? {
                        ...current,
                        refresh:
                          (refresh as Types.CertificateRefreshBehavior) ??
                          Types.CertificateRefreshBehavior.Restart,
                      }
                    : current,
                ),
              )
            }
            disabled={disabled}
            w={150}
          />
          <ActionIcon
            aria-label="Remove certificate attachment"
            color="red"
            variant="subtle"
            disabled={disabled}
            onClick={() =>
              onChange(attachments.filter((_, i) => i !== index))
            }
          >
            <ICONS.Delete size="1rem" />
          </ActionIcon>
        </Group>
      ))}
      <Button
        leftSection={<ICONS.Add size="1rem" />}
        variant="light"
        w="fit-content"
        disabled={disabled || certificateOptions.length === 0}
        onClick={() =>
          onChange([
            ...attachments,
            {
              certificate_id: "",
              service: "",
              mount_path: "/run/secrets/tls",
              refresh: Types.CertificateRefreshBehavior.Restart,
            },
          ])
        }
      >
        Attach certificate
      </Button>
    </Stack>
  );
}
