import { useResourceSelectionState } from "@/lib/hooks";
import { DataTable } from "mogh_ui";
import { Badge, BoxProps, Group } from "@mantine/core";
import { Types } from "komodo_client";
import ResourceLink from "@/resources/link";
import TableTags from "@/components/tags/table";
import { StatusBadge } from "mogh_ui";

export default function CertificateTable({
  resources,
  ...boxProps
}: {
  resources: Types.CertificateListItem[];
} & BoxProps) {
  const selectionState = useResourceSelectionState("Certificate");
  return (
    <DataTable
      {...boxProps}
      tableKey="certificates"
      data={resources}
      selectOptions={{
        selectKey: ({ name }) => name,
        state: selectionState,
      }}
      columns={[
        {
          accessorKey: "name",
          header: "Name",
          cell: ({ row }) => (
            <ResourceLink type="Certificate" id={row.original.id} />
          ),
        },
        {
          accessorKey: "info.domains",
          header: "Domains",
          cell: ({ row }) => (
            <Group gap="xs">
              {row.original.info.domains.map((domain) => (
                <Badge key={domain} variant="light">{domain}</Badge>
              ))}
            </Group>
          ),
        },
        {
          accessorKey: "info.server_name",
          header: "Periphery",
          cell: ({ row }) =>
            row.original.info.server_id ? (
              <ResourceLink type="Server" id={row.original.info.server_id} />
            ) : (
              "Unknown"
            ),
        },
        {
          accessorKey: "info.provider",
          header: "Provider",
        },
        {
          accessorKey: "info.status",
          header: "Status",
          cell: ({ row }) => (
            <StatusBadge
              text={row.original.info.status || "Pending"}
              intent={row.original.info.status === "Ready" ? "Good" : "Warning"}
            />
          ),
        },
        {
          header: "Tags",
          cell: ({ row }) => <TableTags tagIds={row.original.tags} />,
        },
      ]}
    />
  );
}
