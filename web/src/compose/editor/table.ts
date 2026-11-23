import { type Descendant, type Path, type SlateEditor, type TElement, TextApi } from "platejs";

export type Align = "left" | "center" | "right";
export const MAX_INDENT = 8;
export const INDENT_PX = 24;

const FORMAT_MARKS = [
  "bold",
  "italic",
  "underline",
  "strikethrough",
  "fontSize",
  "fontFamily",
  "color",
  "backgroundColor",
] as const;

const ALIGNABLE_TYPES = new Set(["p", "blockquote", "ul", "ol"]);

function emptyCell(header = false): TElement {
  return {
    type: header ? "th" : "td",
    children: [{ type: "p", children: [{ text: "" }] }],
  };
}

function emptyRow(cols: number, header = false): TElement {
  return {
    type: "tr",
    children: Array.from({ length: cols }, () => emptyCell(header)),
  };
}

export function insertTable(editor: SlateEditor, rows: number, cols: number): void {
  const r = Math.min(8, Math.max(1, rows));
  const c = Math.min(8, Math.max(1, cols));
  const table: TElement = {
    type: "table",
    children: Array.from({ length: r }, () => emptyRow(c)),
  };
  editor.tf.insertNodes([table, { type: "p", children: [{ text: "" }] }]);
}

export type TableContext = {
  table: TElement;
  tablePath: Path;
  row: TElement;
  rowPath: Path;
  rowIndex: number;
  cell: TElement;
  cellPath: Path;
  colIndex: number;
};

export function findTableContext(editor: SlateEditor): TableContext | null {
  if (!editor.selection) return null;
  const cellEntry = editor.api.above({
    at: editor.selection,
    match: (n) => !TextApi.isText(n) && (n.type === "td" || n.type === "th"),
  });
  if (!cellEntry) return null;
  const rowEntry = editor.api.above({
    at: cellEntry[1],
    match: (n) => !TextApi.isText(n) && n.type === "tr",
  });
  const tableEntry = editor.api.above({
    at: cellEntry[1],
    match: (n) => !TextApi.isText(n) && n.type === "table",
  });
  if (!rowEntry || !tableEntry) return null;
  const rowPath = rowEntry[1];
  const cellPath = cellEntry[1];
  return {
    table: tableEntry[0] as TElement,
    tablePath: tableEntry[1],
    row: rowEntry[0] as TElement,
    rowPath,
    rowIndex: rowPath[rowPath.length - 1] ?? 0,
    cell: cellEntry[0] as TElement,
    cellPath,
    colIndex: cellPath[cellPath.length - 1] ?? 0,
  };
}

export function isInTable(editor: SlateEditor): boolean {
  return findTableContext(editor) !== null;
}

export function insertTableRow(editor: SlateEditor, above: boolean): void {
  const ctx = findTableContext(editor);
  if (!ctx) return;
  const cols = Math.max(1, ctx.row.children.length);
  const at = [...ctx.tablePath, ctx.rowIndex + (above ? 0 : 1)];
  editor.tf.insertNodes(emptyRow(cols), { at });
}

export function insertTableColumn(editor: SlateEditor, left: boolean): void {
  const ctx = findTableContext(editor);
  if (!ctx) return;
  const colAt = ctx.colIndex + (left ? 0 : 1);
  editor.tf.withoutNormalizing(() => {
    for (let r = 0; r < ctx.table.children.length; r++) {
      const row = ctx.table.children[r] as TElement;
      const isHeader = row.children.some((c) => !TextApi.isText(c) && c.type === "th");
      editor.tf.insertNodes(emptyCell(isHeader), { at: [...ctx.tablePath, r, colAt] });
    }
  });
}

export function deleteTableRow(editor: SlateEditor): void {
  const ctx = findTableContext(editor);
  if (!ctx) return;
  if (ctx.table.children.length <= 1) {
    deleteTable(editor);
    return;
  }
  editor.tf.removeNodes({ at: ctx.rowPath });
}

export function deleteTableColumn(editor: SlateEditor): void {
  const ctx = findTableContext(editor);
  if (!ctx) return;
  if (ctx.row.children.length <= 1) {
    deleteTable(editor);
    return;
  }
  editor.tf.withoutNormalizing(() => {
    for (let r = ctx.table.children.length - 1; r >= 0; r--) {
      const row = ctx.table.children[r] as TElement;
      if (ctx.colIndex < row.children.length) {
        editor.tf.removeNodes({ at: [...ctx.tablePath, r, ctx.colIndex] });
      }
    }
  });
}

export function deleteTable(editor: SlateEditor): void {
  const ctx = findTableContext(editor);
  if (!ctx) return;
  editor.tf.removeNodes({ at: ctx.tablePath });
}

export function moveTableCell(editor: SlateEditor, reverse: boolean): boolean {
  const ctx = findTableContext(editor);
  if (!ctx) return false;
  const rows = ctx.table.children as TElement[];
  let r = ctx.rowIndex;
  let c = ctx.colIndex + (reverse ? -1 : 1);
  if (c < 0) {
    r--;
    if (r < 0) return true;
    c = Math.max(0, rows[r].children.length - 1);
  } else if (c >= rows[r].children.length) {
    r++;
    if (r >= rows.length) return true;
    c = 0;
  }
  const target = [...ctx.tablePath, r, c];
  const point = reverse ? editor.api.end(target) : editor.api.start(target);
  if (point) editor.tf.select(point);
  return true;
}

export function setBlockAlign(editor: SlateEditor, align: Align | null): void {
  editor.tf.setNodes(
    { align: align === "left" || align === null ? undefined : align },
    {
      match: (n) => !TextApi.isText(n) && ALIGNABLE_TYPES.has(String(n.type)),
    },
  );
}

export function stepBlockIndent(editor: SlateEditor, delta: 1 | -1): void {
  const entries = Array.from(
    editor.api.nodes({
      match: (n) => !TextApi.isText(n) && ALIGNABLE_TYPES.has(String(n.type)),
    }),
  );
  editor.tf.withoutNormalizing(() => {
    for (const [node, path] of entries) {
      const cur = typeof node.indent === "number" ? node.indent : 0;
      const next = Math.min(MAX_INDENT, Math.max(0, cur + delta));
      editor.tf.setNodes({ indent: next > 0 ? next : undefined }, { at: path });
    }
  });
}

export function clearFormatting(editor: SlateEditor): void {
  editor.tf.withoutNormalizing(() => {
    for (const mark of FORMAT_MARKS) {
      editor.tf.removeMark(mark);
    }
    editor.tf.setNodes(
      { align: undefined, indent: undefined },
      { match: (n) => !TextApi.isText(n) && ALIGNABLE_TYPES.has(String(n.type)) },
    );
  });
}

export function insertDivider(editor: SlateEditor): void {
  editor.tf.insertNodes([
    { type: "hr", children: [{ text: "" }] } as Descendant,
    { type: "p", children: [{ text: "" }] } as Descendant,
  ]);
}

export function insertBodyImages(editor: SlateEditor, urls: string[]): void {
  if (urls.length === 0) return;
  const nodes: Descendant[] = urls.map((url) => ({
    type: "img",
    url,
    children: [{ text: "" }],
  }));
  nodes.push({ type: "p", children: [{ text: "" }] });
  editor.tf.insertNodes(nodes);
}
