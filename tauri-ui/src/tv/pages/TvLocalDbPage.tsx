import { useCallback, useEffect, useMemo, useState } from "react";
import * as XLSX from "xlsx";
import { Database, Download, Loader2, RefreshCw } from "lucide-react";

import { getTvDbTable, getTvDbTables } from "@/tv/api";
import type { DbTableInfo } from "@/tv/api/types";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable, type ColumnDef } from "@/components/ui/data-table";

const PREVIEW_LIMIT = 500;

type PreviewRow = Record<string, unknown>;

function formatBytes(value?: number): string {
  if (!value) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  const precision = size >= 10 || unitIndex === 0 ? 0 : 1;
  return `${size.toFixed(precision)} ${units[unitIndex]}`;
}

function classifyTable(table: DbTableInfo): {
  label: string;
  variant: "default" | "secondary" | "outline";
} {
  if (table.owned) {
    return { label: "TV", variant: "default" };
  }
  if (table.name.startsWith("sqlite_")) {
    return { label: "SQLite", variant: "secondary" };
  }
  return { label: "Support", variant: "outline" };
}

function pickDefaultTable(tables: DbTableInfo[], preferred?: string | null): string | null {
  if (!tables.length) {
    return null;
  }

  if (preferred && tables.some((table) => table.name === preferred)) {
    return preferred;
  }

  return (
    tables.find((table) => table.owned && table.rowCount > 0)?.name
    ?? tables.find((table) => table.owned)?.name
    ?? tables[0]?.name
    ?? null
  );
}

function renderPreviewValue(value: unknown) {
  if (value == null || value === "") {
    return <span className="text-muted-foreground">-</span>;
  }

  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (!text) {
    return <span className="text-muted-foreground">-</span>;
  }

  const clipped = text.length > 120 ? `${text.slice(0, 120)}...` : text;
  return <span className="font-mono text-xs">{clipped}</span>;
}

export default function TvLocalDbPage() {
  const [tables, setTables] = useState<DbTableInfo[]>([]);
  const [tablesLoading, setTablesLoading] = useState(false);
  const [tablesError, setTablesError] = useState<string | null>(null);
  const [dbPath, setDbPath] = useState<string>("");
  const [dbSizeBytes, setDbSizeBytes] = useState(0);
  const [selectedTable, setSelectedTable] = useState<string | null>(null);

  const [previewRows, setPreviewRows] = useState<PreviewRow[]>([]);
  const [previewColumns, setPreviewColumns] = useState<string[]>([]);
  const [previewTotal, setPreviewTotal] = useState(0);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const loadTables = useCallback(async () => {
    setTablesLoading(true);
    setTablesError(null);

    try {
      const response = await getTvDbTables();
      const nextTables = response.tables ?? [];

      setTables(nextTables);
      setDbPath(response.dbPath ?? "");
      setDbSizeBytes(response.dbSizeBytes ?? 0);
      setSelectedTable((current) => pickDefaultTable(nextTables, current));
    } catch (error) {
      setTablesError(error instanceof Error ? error.message : String(error));
      setTables([]);
      setDbPath("");
      setDbSizeBytes(0);
      setSelectedTable(null);
    } finally {
      setTablesLoading(false);
    }
  }, []);

  const loadPreview = useCallback(async (tableName: string) => {
    setPreviewLoading(true);
    setPreviewError(null);

    try {
      const response = await getTvDbTable(tableName, PREVIEW_LIMIT, 0);
      setPreviewRows(response.rows ?? []);
      setPreviewColumns(response.columns ?? []);
      setPreviewTotal(response.total ?? 0);
    } catch (error) {
      setPreviewError(error instanceof Error ? error.message : String(error));
      setPreviewRows([]);
      setPreviewColumns([]);
      setPreviewTotal(0);
    } finally {
      setPreviewLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadTables();
  }, [loadTables]);

  useEffect(() => {
    if (!selectedTable) {
      setPreviewRows([]);
      setPreviewColumns([]);
      setPreviewTotal(0);
      setPreviewError(null);
      return;
    }

    void loadPreview(selectedTable);
  }, [loadPreview, selectedTable]);

  const tableColumns = useMemo<ColumnDef<DbTableInfo>[]>(() => [
    {
      accessorKey: "name",
      header: "Table",
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs">{row.original.name}</span>
          {selectedTable === row.original.name ? (
            <Badge variant="secondary" className="text-[10px]">Active</Badge>
          ) : null}
        </div>
      ),
    },
    {
      accessorKey: "rowCount",
      header: "Rows",
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {row.original.rowCount.toLocaleString()}
        </span>
      ),
    },
    {
      id: "scope",
      header: "Scope",
      cell: ({ row }) => {
        const scope = classifyTable(row.original);
        return <Badge variant={scope.variant}>{scope.label}</Badge>;
      },
    },
    {
      id: "actions",
      header: "",
      cell: ({ row }) => (
        <Button
          size="sm"
          variant={selectedTable === row.original.name ? "secondary" : "outline"}
          onClick={() => setSelectedTable(row.original.name)}
        >
          {selectedTable === row.original.name ? "Open" : "Preview"}
        </Button>
      ),
    },
  ], [selectedTable]);

  const previewTableColumns = useMemo<ColumnDef<PreviewRow>[]>(() => (
    previewColumns.map((column) => ({
      accessorKey: column,
      header: column,
      cell: ({ row }) => renderPreviewValue(row.original[column]),
    }))
  ), [previewColumns]);

  const ownedTableCount = useMemo(
    () => tables.filter((table) => table.owned).length,
    [tables],
  );

  const totalSavedRows = useMemo(
    () => tables.reduce((sum, table) => sum + table.rowCount, 0),
    [tables],
  );

  const exportPreview = useCallback(() => {
    if (!selectedTable || !previewRows.length) {
      return;
    }

    const worksheet = XLSX.utils.json_to_sheet(previewRows);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "Data");
    XLSX.writeFile(
      workbook,
      `${selectedTable}-${new Date().toISOString().split("T")[0]}.xlsx`,
    );
  }, [previewRows, selectedTable]);

  const activeTable = tables.find((table) => table.name === selectedTable) ?? null;

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-primary/10 text-primary">
              <Database className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-xl font-semibold tracking-tight">Local TV Database</h2>
              <p className="text-sm text-muted-foreground">
                Browse the live MonClub TV SQLite store and preview the rows saved on this machine.
              </p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" onClick={() => void loadTables()} disabled={tablesLoading}>
            {tablesLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            Refresh tables
          </Button>
          <Button
            variant="outline"
            onClick={() => selectedTable && void loadPreview(selectedTable)}
            disabled={!selectedTable || previewLoading}
          >
            {previewLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            Refresh preview
          </Button>
          <Button variant="outline" onClick={exportPreview} disabled={!previewRows.length}>
            <Download className="h-4 w-4" />
            Export preview
          </Button>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Tables</CardDescription>
            <CardTitle className="text-2xl">{tables.length.toLocaleString()}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>TV-owned tables</CardDescription>
            <CardTitle className="text-2xl">{ownedTableCount.toLocaleString()}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Saved rows</CardDescription>
            <CardTitle className="text-2xl">{totalSavedRows.toLocaleString()}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>DB size</CardDescription>
            <CardTitle className="text-2xl">{formatBytes(dbSizeBytes)}</CardTitle>
          </CardHeader>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardDescription>Database file</CardDescription>
          <CardTitle className="text-base">Runtime path</CardTitle>
        </CardHeader>
        <CardContent>
          <code className="block rounded-lg border border-dashed border-border bg-muted/30 px-3 py-2 text-xs break-all">
            {dbPath || "No TV database path reported yet."}
          </code>
        </CardContent>
      </Card>

      {tablesError ? (
        <Alert variant="destructive">
          <AlertDescription>{tablesError}</AlertDescription>
        </Alert>
      ) : null}

      <div className="grid gap-6 2xl:grid-cols-[minmax(420px,0.95fr)_minmax(0,1.55fr)]">
        <Card className="min-w-0">
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Local tables</CardTitle>
            <CardDescription>
              Every table currently present in the TV local database, including support metadata tables.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={tableColumns}
              data={tables}
              loading={tablesLoading}
              pageSize={10}
              searchKey="name"
              searchPlaceholder="Find a table..."
              emptyMessage="No local TV tables were found."
              emptyDescription="Start the TV runtime once to let the local database initialize."
            />
          </CardContent>
        </Card>

        <Card className="min-w-0">
          <CardHeader className="pb-3">
            <div className="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
              <div className="space-y-1">
                <CardTitle className="flex items-center gap-2 text-base">
                  <span>Table preview</span>
                  {activeTable ? <Badge>{activeTable.name}</Badge> : null}
                </CardTitle>
                <CardDescription>
                  Showing up to the first {PREVIEW_LIMIT.toLocaleString()} rows from the selected table.
                </CardDescription>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="secondary">
                  {previewRows.length.toLocaleString()} / {previewTotal.toLocaleString()} rows loaded
                </Badge>
                {activeTable ? (
                  <Badge variant={classifyTable(activeTable).variant}>
                    {classifyTable(activeTable).label}
                  </Badge>
                ) : null}
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {previewError ? (
              <Alert variant="destructive">
                <AlertDescription>{previewError}</AlertDescription>
              </Alert>
            ) : null}

            {selectedTable ? (
              <DataTable
                columns={previewTableColumns}
                data={previewRows}
                loading={previewLoading}
                pageSize={20}
                searchKey={previewColumns[0]}
                searchPlaceholder="Search the current preview..."
                emptyMessage="This table is empty."
                emptyDescription="No rows have been stored locally for the selected table yet."
              />
            ) : (
              <div className="flex h-56 items-center justify-center rounded-xl border border-dashed border-border text-sm text-muted-foreground">
                Select a table to inspect its saved rows.
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
