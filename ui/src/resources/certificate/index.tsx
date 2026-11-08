import { useExecute, useListItem, useRead } from "@/lib/hooks";
import { ICONS } from "@/lib/icons";
import ResourceHeader from "@/resources/header";
import { RequiredResourceComponents } from "@/resources";
import { Types } from "komodo_client";
import { Badge, Button, Group, Text } from "@mantine/core";
import { StatusBadge } from "mogh_ui";
import ResourceLink from "@/resources/link";
import BatchExecutions from "@/resources/batch-executions";
import CertificateTable from "./table";
import CertificateConfig from "./config";
import NewCertificate from "./new";

export function useCertificate(
  id: string | undefined,
  useName?: boolean,
  refetchInterval?: number | false,
) {
  return useListItem("Certificate", id, useName, refetchInterval);
}

export function useFullCertificate(id: string) {
  return useRead(
    "GetCertificate",
    { certificate: id },
    { refetchInterval: 30_000 },
  ).data;
}

export const CertificateComponents: RequiredResourceComponents<
  Types.CertificateConfig,
  Types.CertificateInfo,
  Types.CertificateListItemInfo,
  Types.CertificateQuerySpecifics
> = {
  useList: (query, limit, page) =>
    useRead("ListCertificates", { query, limit, page }).data,
  useListItem: useCertificate,
  useFull: useFullCertificate,
  useResourceLinks: () => undefined,
  Description: () => (
    <>
      Certificates are issued and stored on their assigned Unix Periphery host.
      Private keys and ACME state never leave that host.
    </>
  ),
  New: NewCertificate,
  BatchExecutions: () => <BatchExecutions type="Certificate" executions={[]} />,
  Table: CertificateTable,
  Icon: ({ size = "1rem", noColor }) => (
    <ICONS.Certificate size={size} color={noColor ? undefined : "var(--mantine-color-blue-5)"} />
  ),
  ResourcePageHeader: ({ id }) => {
    const certificate = useCertificate(id);
    return (
      <ResourceHeader
        type="Certificate"
        id={id}
        resource={certificate}
        intent={certificate?.info.status === "Ready" ? "Good" : "Warning"}
        icon={ICONS.Certificate}
        name={certificate?.name}
        state={certificate?.info.status || "Pending"}
      />
    );
  },
  State: ({ id }) => {
    const status = useCertificate(id)?.info.status;
    return (
      <StatusBadge
        text={status || "Pending"}
        intent={status === "Ready" ? "Good" : status ? "Warning" : "Neutral"}
      />
    );
  },
  Info: {
    Server: ({ id }) => {
      const info = useCertificate(id)?.info;
      return info?.server_id ? (
        <ResourceLink type="Server" id={info.server_id} />
      ) : null;
    },
    Domains: ({ id }) => {
      const domains = useCertificate(id)?.info.domains;
      return domains?.length ? (
        <Group gap="xs">
          {domains.map((domain) => (
            <Badge key={domain} variant="light">{domain}</Badge>
          ))}
        </Group>
      ) : null;
    },
    LastIssued: ({ id }) => {
      const lastIssued = useCertificate(id)?.info.last_issued;
      return lastIssued ? (
        <Text size="sm">
          Last issued: {new Date(lastIssued * 1000).toLocaleString()}
        </Text>
      ) : null;
    },
  },
  Executions: {
    Renew: ({ id }) => {
      const { mutate, isPending } = useExecute("RenewCertificate");
      return (
        <Button
          leftSection={<ICONS.Refresh size="1rem" />}
          loading={isPending}
          disabled={isPending}
          onClick={() => mutate({ certificate: id })}
        >
          Check / Renew Certificate
        </Button>
      );
    },
  },
  Config: CertificateConfig,
  Page: {},
};
