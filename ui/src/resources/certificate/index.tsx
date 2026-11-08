import {
  useListItem,
  usePermissions,
  useRead,
  useResourceSelectionState,
  useWrite,
} from "@/lib/hooks";
import { ICONS } from "@/lib/icons";
import { RequiredResourceComponents } from "..";
import { Types } from "komodo_client";
import NewResource from "@/resources/new";
import ResourceHeader from "../header";
import ResourceLink from "@/resources/link";
import {
  Badge,
  BoxProps,
  Button,
  Group,
  Select,
  Stack,
  Text,
  TextInput,
} from "@mantine/core";
import { DataTable, SortableHeader, StatusBadge } from "mogh_ui";
import { useLocalStorage } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { useState } from "react";

function useCertificate(
  id: string | undefined,
  useName?: boolean,
  refetchInterval?: number | false,
) {
  return useListItem("Certificate", id, useName, refetchInterval);
}

function useFullCertificate(id: string) {
  return useRead(
    "GetCertificate",
    { certificate: id },
    { refetchInterval: 30_000 },
  ).data;
}

export const CertificateComponents: RequiredResourceComponents<
  Types.CertificateConfig,
  Types.CertificateInfo,
  Types.CertificateListItemInfo
> = {
  useList: (query, limit, page) =>
    useRead("ListCertificates", { query, limit, page }).data,
  useListItem: useCertificate,
  useFull: useFullCertificate,
  useResourceLinks: () => undefined,

  Description: () => (
    <>Manage certificate requests for Cloudflare DNS and Tailscale.</>
  ),

  New: ({ serverId }) => <NewCertificate serverId={serverId} />,
  BatchExecutions: () => null,
  Table: CertificateTable,

  Icon: ({ size = "1rem", noColor }) => (
    <ICONS.Certificate
      size={size}
      color={noColor ? undefined : "currentColor"}
    />
  ),

  ResourcePageHeader: ({ id }) => {
    const certificate = useCertificate(id);
    return (
      <ResourceHeader
        type="Certificate"
        id={id}
        resource={certificate}
        intent={
          certificate?.info.status === Types.CertificateStatus.Ready
            ? "Good"
            : certificate?.info.status === Types.CertificateStatus.Error
              ? "Critical"
              : "Warning"
        }
        icon={ICONS.Certificate}
        name={certificate?.name}
        state={certificate?.info.status ?? "Pending"}
        status={certificate?.info.domains.join(", ")}
      />
    );
  },

  State: ({ id }) => {
    const status = useCertificate(id)?.info.status;
    return (
      <StatusBadge
        text={status ?? "Pending"}
        intent={
          status === Types.CertificateStatus.Ready
            ? "Good"
            : status === Types.CertificateStatus.Error
              ? "Critical"
              : "Warning"
        }
      />
    );
  },
  Config: CertificateConfig,
  Info: {},
  Executions: {},
  Page: {},
};

function CertificateTable({
  resources,
  onServerSort,
  ...boxProps
}: {
  resources: Types.CertificateListItem[];
  onServerSort?: (sort: {
    sort_by?: string;
    sort_desc?: boolean;
  }) => void;
} & BoxProps) {
  const selectionState = useResourceSelectionState("Certificate");
  return (
    <DataTable
      {...boxProps}
      manualSorting={!!onServerSort}
      onSortingStateChange={
        onServerSort &&
        ((sorting) => {
          const sort = sorting.find((item) => item.id === "Name");
          onServerSort(
            sort ? { sort_by: sort.id, sort_desc: sort.desc } : {},
          );
        })
      }
      tableKey="certificates"
      data={resources}
      selectOptions={{
        selectKey: ({ name }) => name,
        state: selectionState,
      }}
      columns={[
        {
          id: "Name",
          accessorKey: "name",
          header: ({ column }) => (
            <SortableHeader column={column} title="Name" />
          ),
          cell: ({ row }) => (
            <ResourceLink type="Certificate" id={row.original.id} />
          ),
        },
        {
          header: "Domains",
          cell: ({ row }) => row.original.info.domains.join(", "),
        },
        {
          header: "Issuer",
          cell: ({ row }) => (
            <Badge>
              {row.original.info.issuer.type === "tailscale"
                ? "Tailscale"
                : "Cloudflare ACME"}
            </Badge>
          ),
        },
        {
          header: "Status",
          cell: ({ row }) => (
            <CertificateComponents.State id={row.original.id} />
          ),
        },
        {
          header: "Expires",
          cell: ({ row }) => {
            const expiresAt = row.original.info.expires_at;
            return expiresAt
              ? new Date(Number(expiresAt) * 1000).toLocaleDateString()
              : "Unknown";
          },
        },
      ]}
    />
  );
}

function NewCertificate({ serverId }: { serverId?: string }) {
  const servers = useRead("ListServers", {}).data ?? [];
  const [selectedServer, setSelectedServer] = useState(serverId ?? "");
  const [domainsInput, setDomainsInput] = useState("");
  const [issuerType, setIssuerType] = useState("acme_cloudflare");
  const [apiTokenSecret, setApiTokenSecret] = useState("");
  const [email, setEmail] = useState("");

  const issuer: Types.CertificateIssuer =
    issuerType === "tailscale"
      ? { type: "tailscale" }
      : {
          type: "acme_cloudflare",
          params: { api_token_secret: apiTokenSecret, email },
        };

  return (
    <NewResource<Types.CertificateConfig>
      type="Certificate"
      showTemplateSelector={false}
      config={() => ({
        server_id: selectedServer,
        domains: domainsInput
          .split(",")
          .map((domain) => domain.trim())
          .filter(Boolean),
        issuer,
      })}
      extraInputs={
        <Stack>
          <Select
            label="Server"
            data={servers.map((server) => ({
              label: server.name,
              value: server.id,
            }))}
            value={selectedServer}
            onChange={(value) => setSelectedServer(value ?? "")}
            searchable
            required
          />
          <TextInput
            label="DNS names"
            description="Enter comma-separated fully qualified DNS names."
            value={domainsInput}
            onChange={(event) => setDomainsInput(event.currentTarget.value)}
            required
          />
          <Select
            label="Issuer"
            data={[
              { label: "ACME via Cloudflare", value: "acme_cloudflare" },
              { label: "Tailscale", value: "tailscale" },
            ]}
            value={issuerType}
            onChange={(value) => setIssuerType(value ?? "acme_cloudflare")}
            required
          />
          {issuerType === "acme_cloudflare" && (
            <>
              <TextInput
                label="Cloudflare API token secret name"
                description="References a secret configured in Komodo Core; the token is not stored in this resource."
                value={apiTokenSecret}
                onChange={(event) =>
                  setApiTokenSecret(event.currentTarget.value)
                }
                required
              />
              <TextInput
                label="ACME account email"
                value={email}
                onChange={(event) => setEmail(event.currentTarget.value)}
              />
            </>
          )}
        </Stack>
      }
    />
  );
}

function CertificateConfig({ id }: { id: string }) {
  const certificate = useFullCertificate(id);
  const { canWrite } = usePermissions({ type: "Certificate", id });
  const globalDisabled =
    useRead("GetCoreInfo", {}).data?.ui_write_disabled ?? false;
  const servers = useRead("ListServers", {}).data ?? [];
  const { mutateAsync, isPending } = useWrite("UpdateCertificate");
  const [update, setUpdate] =
    useLocalStorage<Partial<Types.CertificateConfig>>({
      key: `certificate-${id}-update-v1`,
      defaultValue: {},
    });

  if (!certificate) return null;

  const config = certificate.config;
  const issuer = update.issuer ?? config?.issuer;
  const issuerType = issuer?.type ?? "acme_cloudflare";
  const params =
    issuerType === "acme_cloudflare" && issuer?.type === "acme_cloudflare"
      ? issuer.params
      : undefined;
  const disabled = globalDisabled || !canWrite || isPending;

  const onSave = async () => {
    try {
      await mutateAsync({ id, config: update });
      notifications.show({
        message: "Certificate settings saved",
        color: "green",
      });
    } catch (error) {
      notifications.show({
        message:
          error instanceof Error
            ? error.message
            : "Failed to save certificate settings",
        color: "red",
      });
    }
  };

  return (
    <Stack maw={720}>
      <Select
        label="Server"
        data={servers.map((server) => ({
          label: server.name,
          value: server.id,
        }))}
        value={update.server_id ?? config?.server_id ?? ""}
        onChange={(server_id) =>
          setUpdate({ ...update, server_id: server_id ?? "" })
        }
        searchable
        disabled
      />
      <TextInput
        label="DNS names"
        description="Enter comma-separated fully qualified DNS names."
        value={(update.domains ?? config?.domains ?? []).join(", ")}
        onChange={(event) =>
          setUpdate({
            ...update,
            domains: event.currentTarget.value
              .split(",")
              .map((domain) => domain.trim())
              .filter(Boolean),
          })
        }
        disabled={disabled}
      />
      <Select
        label="Issuer"
        data={[
          { label: "ACME via Cloudflare", value: "acme_cloudflare" },
          { label: "Tailscale", value: "tailscale" },
        ]}
        value={issuerType}
        onChange={(type) =>
          setUpdate({
            ...update,
            issuer:
              type === "tailscale"
                ? { type: "tailscale" }
                : {
                    type: "acme_cloudflare",
                    params: {
                      api_token_secret: params?.api_token_secret ?? "",
                      email: params?.email ?? "",
                    },
                  },
          })
        }
        disabled={disabled}
      />
      {issuerType === "acme_cloudflare" && (
        <>
          <TextInput
            label="Cloudflare API token secret name"
            value={params?.api_token_secret ?? ""}
            onChange={(event) =>
              setUpdate({
                ...update,
                issuer: {
                  type: "acme_cloudflare",
                  params: {
                    api_token_secret: event.currentTarget.value,
                    email: params?.email ?? "",
                  },
                },
              })
            }
            disabled={disabled}
          />
          <TextInput
            label="ACME account email"
            value={params?.email ?? ""}
            onChange={(event) =>
              setUpdate({
                ...update,
                issuer: {
                  type: "acme_cloudflare",
                  params: {
                    api_token_secret: params?.api_token_secret ?? "",
                    email: event.currentTarget.value,
                  },
                },
              })
            }
            disabled={disabled}
          />
        </>
      )}
      <Group justify="space-between">
        <StatusBadge
          text={certificate.info?.status ?? "Pending"}
          intent={
            certificate.info?.status === Types.CertificateStatus.Ready
              ? "Good"
              : certificate.info?.status === Types.CertificateStatus.Error
                ? "Critical"
                : "Warning"
          }
        />
        {certificate.info?.last_error && (
          <Text c="red" size="sm">
            {certificate.info.last_error}
          </Text>
        )}
        <Button onClick={onSave} loading={isPending} disabled={disabled}>
          Save
        </Button>
      </Group>
    </Stack>
  );
}
