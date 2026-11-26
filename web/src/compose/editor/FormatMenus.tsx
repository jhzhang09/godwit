import {
  type RemixiconComponentType,
  RiAddLine,
  RiAlignCenter,
  RiAlignLeft,
  RiAlignRight,
  RiCheckLine,
  RiDeleteBinLine,
  RiDeleteColumn,
  RiDeleteRow,
  RiFontColor,
  RiFontFamily,
  RiFontSize,
  RiFormatClear,
  RiImageAddLine,
  RiIndentDecrease,
  RiIndentIncrease,
  RiInsertColumnLeft,
  RiInsertColumnRight,
  RiInsertRowBottom,
  RiInsertRowTop,
  RiSeparator,
  RiTable2,
} from "@remixicon/react";
import { TextApi, type TRange } from "platejs";
import { useEditorReadOnly, useEditorRef, useEditorSelector } from "platejs/react";
import { type RefObject, useState } from "react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { T } from "@/shared/i18n";
import {
  type Align,
  clearFormatting,
  deleteTable,
  deleteTableColumn,
  deleteTableRow,
  insertDivider,
  insertTable,
  insertTableColumn,
  insertTableRow,
  isInTable,
  setBlockAlign,
  stepBlockIndent,
} from "./table";

const TEXT_COLORS = [
  "#1f2937",
  "#6b7280",
  "#dc2626",
  "#ea580c",
  "#d97706",
  "#16a34a",
  "#0d9488",
  "#2563eb",
  "#7c3aed",
  "#db2777",
];

const HIGHLIGHT_COLORS = [
  "#fef08a",
  "#fed7aa",
  "#fecaca",
  "#bbf7d0",
  "#bfdbfe",
  "#e9d5ff",
  "#fbcfe8",
  "#e5e7eb",
];

const TRIGGER_CLS =
  "inline-flex size-7 items-center justify-center rounded-md text-foreground/80 hover:bg-accent hover:text-accent-foreground disabled:opacity-50";

export const FONT_SIZES = [
  { label: "", value: "" }, // compose.size_default
  { label: "9 pt", value: "9pt" },
  { label: "10 pt", value: "10pt" },
  { label: "11 pt", value: "11pt" },
  { label: "12 pt", value: "12pt" },
  { label: "13 pt", value: "13pt" },
  { label: "14 pt", value: "14pt" },
  { label: "18 pt", value: "18pt" },
  { label: "24 pt", value: "24pt" },
  { label: "36 pt", value: "36pt" },
];

export const FONTS = [
  { label: "", value: "" }, // compose.font_default
  { label: "Arial", value: "Arial, sans-serif" },
  { label: "Courier New", value: "'Courier New', Courier, monospace" },
  { label: "Georgia", value: "Georgia, serif" },
  { label: "Helvetica", value: "Helvetica, Arial, sans-serif" },
  { label: "Palatino", value: "Palatino, 'Palatino Linotype', serif" },
  { label: "Tahoma", value: "Tahoma, Verdana, sans-serif" },
  { label: "Times New Roman", value: "'Times New Roman', Times, serif" },
  { label: "Trebuchet MS", value: "'Trebuchet MS', sans-serif" },
  { label: "Verdana", value: "Verdana, sans-serif" },
];

// The browser re-quotes a font list it reads back (`'A B'` becomes `"A B"`), so compare without quotes.
const unquoted = (s: string) => s.replace(/["']/g, "");

type MenuProps = {
  t: T;
  saved: RefObject<TRange | null>;
  triggerClassName?: string;
};

function FontMenu({
  t,
  saved,
  mark,
  label,
  Icon,
  options,
  defaultLabel,
  className,
  triggerClassName,
}: MenuProps & {
  mark: "fontFamily" | "fontSize";
  label: string;
  Icon: RemixiconComponentType;
  options: { label: string; value: string }[];
  defaultLabel: string;
  className: string;
}) {
  const editor = useEditorRef();
  const readOnly = useEditorReadOnly();
  const current = useEditorSelector((e) => {
    const m = e.selection ? e.api.marks() : null;
    return String(m?.[mark] ?? "");
  }, []);

  const applyMark = (val: string) => {
    if (saved.current) editor.tf.select(saved.current);
    if (val) editor.tf.addMark(mark, val);
    else editor.tf.removeMark(mark);
    saved.current = editor.selection; // the mark split the text: the old range points elsewhere
    editor.tf.focus();
  };

  return (
    <DropdownMenu
      modal={false}
      highlightItemOnHover={false}
      onOpenChange={(open) => {
        if (open) {
          saved.current = editor.selection;
        } else {
          setTimeout(() => {
            if (saved.current) editor.tf.select(saved.current);
            editor.tf.focus();
          }, 0);
        }
      }}
    >
      <Tooltip>
        <TooltipTrigger
          render={
            <DropdownMenuTrigger
              aria-label={t(label)}
              disabled={readOnly}
              onMouseDown={(e) => {
                saved.current = editor.selection;
                e.preventDefault();
              }}
              className={triggerClassName ?? TRIGGER_CLS}
            >
              <Icon className="size-3.75" />
            </DropdownMenuTrigger>
          }
        />
        <TooltipContent>{t(label)}</TooltipContent>
      </Tooltip>
      <DropdownMenuContent
        align="start"
        className={`w-auto max-h-[min(15rem,var(--available-height))] overflow-y-auto ${className}`}
        onMouseDown={(e) => e.preventDefault()}
      >
        {options.map((o) => (
          <DropdownMenuItem
            key={o.value}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => applyMark(o.value)}
            style={mark === "fontFamily" ? { fontFamily: o.value || "inherit" } : undefined}
            className="flex items-center justify-between gap-3"
          >
            <span className="whitespace-nowrap">{o.label || defaultLabel}</span>
            {unquoted(current) === unquoted(o.value) && (
              <RiCheckLine className="ml-2 size-3.5 shrink-0 text-primary" />
            )}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function FontFamilyMenu({ t, saved, triggerClassName }: MenuProps) {
  return (
    <FontMenu
      t={t}
      saved={saved}
      mark="fontFamily"
      label="compose.font_family"
      Icon={RiFontFamily}
      options={FONTS}
      defaultLabel={t("compose.font_default")}
      className="min-w-56"
      triggerClassName={triggerClassName}
    />
  );
}

export function FontSizeMenu({ t, saved, triggerClassName }: MenuProps) {
  return (
    <FontMenu
      t={t}
      saved={saved}
      mark="fontSize"
      label="compose.font_size"
      Icon={RiFontSize}
      options={FONT_SIZES}
      defaultLabel={t("compose.size_default", "14 pt")}
      className="min-w-44"
      triggerClassName={triggerClassName}
    />
  );
}

export function ColorMenu({ t, saved, triggerClassName }: MenuProps) {
  const editor = useEditorRef();
  const readOnly = useEditorReadOnly();
  const [open, setOpen] = useState(false);

  const active = useEditorSelector((e) => {
    const m = e.selection ? e.api.marks() : null;
    return `${m?.color ?? ""}\n${m?.backgroundColor ?? ""}`;
  }, []);
  const [currentColor, currentBg] = active.split("\n");

  const apply = (key: "color" | "backgroundColor", val: string) => {
    if (saved.current) editor.tf.select(saved.current);
    if (val) editor.tf.addMark(key, val);
    else editor.tf.removeMark(key);
    saved.current = editor.selection;
    setOpen(false);
    editor.tf.focus();
  };

  return (
    <Popover
      open={open}
      onOpenChange={(next) => {
        if (next) saved.current = editor.selection;
        setOpen(next);
      }}
    >
      <Tooltip>
        <TooltipTrigger
          render={
            <PopoverTrigger
              render={
                <button
                  type="button"
                  aria-label={t("compose.color")}
                  disabled={readOnly}
                  onMouseDown={(e) => {
                    saved.current = editor.selection;
                    e.preventDefault();
                  }}
                  className={`${triggerClassName ?? TRIGGER_CLS} relative`}
                >
                  <RiFontColor className="size-3.75" />
                  <span
                    className="absolute bottom-1 left-1.5 right-1.5 h-0.5 rounded-full"
                    style={{ backgroundColor: currentColor || "currentColor" }}
                  />
                </button>
              }
            />
          }
        />
        <TooltipContent>{t("compose.color")}</TooltipContent>
      </Tooltip>
      <PopoverContent
        align="start"
        className="w-56 max-h-(--available-height) overflow-y-auto p-2.5"
        onMouseDown={(e) => e.preventDefault()}
      >
        <div className="space-y-2.5">
          <div>
            <div className="mb-1.5 flex items-center justify-between text-[11px] text-muted-foreground">
              <span>{t("compose.text_color")}</span>
              <button
                type="button"
                onClick={() => apply("color", "")}
                className="rounded px-1.5 py-0.5 text-[11px] hover:bg-accent hover:text-accent-foreground"
              >
                {t("compose.color_default")}
              </button>
            </div>
            <div className="grid grid-cols-5 gap-1.5">
              {TEXT_COLORS.map((c) => (
                <button
                  key={c}
                  type="button"
                  aria-label={c}
                  onClick={() => apply("color", c)}
                  className={`size-6 rounded border transition-transform hover:scale-110 ${
                    currentColor === c ? "ring-2 ring-primary ring-offset-1" : "border-border/70"
                  }`}
                  style={{ backgroundColor: c }}
                />
              ))}
            </div>
          </div>
          <Separator />
          <div>
            <div className="mb-1.5 flex items-center justify-between text-[11px] text-muted-foreground">
              <span>{t("compose.highlight_color")}</span>
              <button
                type="button"
                onClick={() => apply("backgroundColor", "")}
                className="rounded px-1.5 py-0.5 text-[11px] hover:bg-accent hover:text-accent-foreground"
              >
                {t("compose.color_none")}
              </button>
            </div>
            <div className="grid grid-cols-4 gap-1.5">
              {HIGHLIGHT_COLORS.map((c) => (
                <button
                  key={c}
                  type="button"
                  aria-label={c}
                  onClick={() => apply("backgroundColor", c)}
                  className={`size-6 rounded border transition-transform hover:scale-110 ${
                    currentBg === c ? "ring-2 ring-primary ring-offset-1" : "border-border/70"
                  }`}
                  style={{ backgroundColor: c }}
                />
              ))}
            </div>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}

export function LayoutMenu({ t, saved }: MenuProps) {
  const editor = useEditorRef();
  const readOnly = useEditorReadOnly();

  const currentAlign = useEditorSelector((e) => {
    if (!e.selection) return "left";
    const entry = e.api.above({
      at: e.selection,
      match: (n) =>
        !TextApi.isText(n) &&
        (n.type === "p" || n.type === "blockquote" || n.type === "ul" || n.type === "ol"),
    });
    const a = entry?.[0]?.align;
    return a === "center" || a === "right" ? a : "left";
  }, []) as Align;

  const AlignIcon =
    currentAlign === "center"
      ? RiAlignCenter
      : currentAlign === "right"
        ? RiAlignRight
        : RiAlignLeft;

  const run = (fn: () => void) => {
    if (saved.current) editor.tf.select(saved.current);
    fn();
    saved.current = editor.selection;
    editor.tf.focus();
  };

  return (
    <DropdownMenu
      modal={false}
      highlightItemOnHover={false}
      onOpenChange={(open) => {
        if (open) {
          saved.current = editor.selection;
        } else {
          setTimeout(() => {
            if (saved.current) editor.tf.select(saved.current);
            editor.tf.focus();
          }, 0);
        }
      }}
    >
      <Tooltip>
        <TooltipTrigger
          render={
            <DropdownMenuTrigger
              aria-label={t("compose.layout")}
              disabled={readOnly}
              onMouseDown={(e) => {
                saved.current = editor.selection;
                e.preventDefault();
              }}
              className={TRIGGER_CLS}
            >
              <AlignIcon className="size-3.75" />
            </DropdownMenuTrigger>
          }
        />
        <TooltipContent>{t("compose.layout")}</TooltipContent>
      </Tooltip>
      <DropdownMenuContent align="start" className="w-48" onMouseDown={(e) => e.preventDefault()}>
        {(
          [
            ["left", "compose.align_left", RiAlignLeft],
            ["center", "compose.align_center", RiAlignCenter],
            ["right", "compose.align_right", RiAlignRight],
          ] as const
        ).map(([val, label, Icon]) => (
          <DropdownMenuItem
            key={val}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => run(() => setBlockAlign(editor, val))}
            className="flex items-center justify-between gap-2"
          >
            <span className="flex items-center gap-2">
              <Icon className="size-3.75" />
              <span>{t(label)}</span>
            </span>
            {currentAlign === val && <RiCheckLine className="size-3.5 text-primary" />}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => run(() => stepBlockIndent(editor, 1))}
          className="flex items-center gap-2"
        >
          <RiIndentIncrease className="size-3.75" />
          <span>{t("compose.indent_increase")}</span>
        </DropdownMenuItem>
        <DropdownMenuItem
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => run(() => stepBlockIndent(editor, -1))}
          className="flex items-center gap-2"
        >
          <RiIndentDecrease className="size-3.75" />
          <span>{t("compose.indent_decrease")}</span>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => run(() => clearFormatting(editor))}
          className="flex items-center gap-2"
        >
          <RiFormatClear className="size-3.75" />
          <span>{t("compose.clear_format")}</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function InsertMenu({ t, saved, onPickImages }: MenuProps & { onPickImages?: () => void }) {
  const editor = useEditorRef();
  const readOnly = useEditorReadOnly();
  const [open, setOpen] = useState(false);
  const [hover, setHover] = useState<[number, number]>([0, 0]);
  const inTable = useEditorSelector((e) => isInTable(e), []);

  const run = (fn: () => void) => {
    if (saved.current) editor.tf.select(saved.current);
    fn();
    saved.current = editor.selection;
    setOpen(false);
    editor.tf.focus();
  };

  const rows = hover[0] || 3;
  const cols = hover[1] || 3;

  return (
    <Popover
      open={open}
      onOpenChange={(next) => {
        if (next) {
          saved.current = editor.selection;
          setHover([0, 0]);
        }
        setOpen(next);
      }}
    >
      <Tooltip>
        <TooltipTrigger
          render={
            <PopoverTrigger
              render={
                <button
                  type="button"
                  aria-label={t("compose.insert")}
                  disabled={readOnly}
                  onMouseDown={(e) => {
                    saved.current = editor.selection;
                    e.preventDefault();
                  }}
                  className={TRIGGER_CLS}
                >
                  <RiAddLine className="size-4" />
                </button>
              }
            />
          }
        />
        <TooltipContent>{t("compose.insert")}</TooltipContent>
      </Tooltip>
      <PopoverContent align="start" className="w-56 p-1.5" onMouseDown={(e) => e.preventDefault()}>
        <div className="space-y-1">
          {onPickImages && (
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                onPickImages();
              }}
              className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-xs hover:bg-accent hover:text-accent-foreground"
            >
              <RiImageAddLine className="size-3.75" />
              <span>{t("compose.insert_image")}</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => run(() => insertDivider(editor))}
            className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-xs hover:bg-accent hover:text-accent-foreground"
          >
            <RiSeparator className="size-3.75" />
            <span>{t("compose.insert_divider")}</span>
          </button>
          <Separator className="my-1" />
          <div className="px-2 py-1">
            <div className="mb-1.5 flex items-center justify-between text-[11px] text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <RiTable2 className="size-3.5" />
                {t("compose.insert_table")}
              </span>
              <span>{t("compose.table_size", rows, cols)}</span>
            </div>
            <fieldset
              className="m-0 grid grid-cols-6 gap-1 border-0 p-0"
              onMouseLeave={() => setHover([0, 0])}
            >
              {Array.from({ length: 6 }, (_, rIdx) =>
                Array.from({ length: 6 }, (_, cIdx) => {
                  const r = rIdx + 1;
                  const c = cIdx + 1;
                  const active = r <= hover[0] && c <= hover[1];
                  return (
                    <button
                      key={`${r}-${c}`}
                      type="button"
                      aria-label={t("compose.table_size", r, c)}
                      onMouseEnter={() => setHover([r, c])}
                      onClick={() => run(() => insertTable(editor, r, c))}
                      className={`size-5 rounded-[3px] border transition-colors ${
                        active
                          ? "border-primary bg-primary/20"
                          : "border-border bg-muted/30 hover:border-primary/60"
                      }`}
                    />
                  );
                }),
              )}
            </fieldset>
          </div>
          {inTable && (
            <>
              <Separator className="my-1" />
              <div className="space-y-0.5">
                {(
                  [
                    ["compose.table_row_above", RiInsertRowTop, () => insertTableRow(editor, true)],
                    [
                      "compose.table_row_below",
                      RiInsertRowBottom,
                      () => insertTableRow(editor, false),
                    ],
                    [
                      "compose.table_col_left",
                      RiInsertColumnLeft,
                      () => insertTableColumn(editor, true),
                    ],
                    [
                      "compose.table_col_right",
                      RiInsertColumnRight,
                      () => insertTableColumn(editor, false),
                    ],
                    ["compose.table_delete_row", RiDeleteRow, () => deleteTableRow(editor)],
                    ["compose.table_delete_col", RiDeleteColumn, () => deleteTableColumn(editor)],
                    ["compose.table_delete", RiDeleteBinLine, () => deleteTable(editor)],
                  ] as const
                ).map(([label, Icon, act]) => (
                  <button
                    key={label}
                    type="button"
                    onClick={() => run(act)}
                    className="flex w-full items-center gap-2 rounded-sm px-2 py-1 text-left text-xs hover:bg-accent hover:text-accent-foreground"
                  >
                    <Icon className="size-3.5" />
                    <span>{t(label)}</span>
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}
