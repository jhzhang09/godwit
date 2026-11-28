import {
  BlockquotePlugin,
  BoldPlugin,
  ItalicPlugin,
  StrikethroughPlugin,
  UnderlinePlugin,
} from "@platejs/basic-nodes/react";
import { LinkPlugin } from "@platejs/link/react";
import { ListPlugin, TaskListPlugin } from "@platejs/list-classic/react";
import { type AnyPluginConfig, createSlatePlugin, NodeApi, TextApi } from "platejs";
import {
  createPlatePlugin,
  ParagraphPlugin,
  PlateElement,
  type PlateElementProps,
} from "platejs/react";
import React, { createContext, useContext } from "react";
import { CID_SRC, deserialize, IMAGE_SRC, safeHref, toHTML } from "./html";

/**
 * Owns paste and drop: nothing reaches Plate's parsers or Slate's fragment insert. A Slate
 * fragment goes through toHTML with only images already owned by this draft.
 * HTML takes fromHTML's path (inert parse, loaders stripped); when that yields nothing, the plain
 * text goes in as paragraphs. Files are not taken.
 */
export const SafePastePlugin = createSlatePlugin({
  key: "safePaste",
  options: { images: {} as Record<string, string> },
}).overrideEditor(({ editor, getOption }) => ({
  transforms: {
    insertData(data: DataTransfer) {
      let html = data.getData("text/html");
      let hasImage = false;
      // Slate also writes its fragment into HTML for clipboards that omit custom MIME types.
      const fragment =
        data.getData("application/x-slate-fragment") ||
        html.match(/\sdata-slate-fragment="([A-Za-z0-9+/=]+)"/)?.[1];
      if (fragment) {
        try {
          const value = JSON.parse(decodeURIComponent(atob(fragment)));
          const images = getOption("images");
          for (const [node] of NodeApi.elements({ type: "fragment", children: value })) {
            if (node.type !== "img") continue;
            const src = String(node.url ?? "");
            if (!CID_SRC.test(src) || !Object.hasOwn(images, src.slice(4))) delete node.url;
          }
          html = toHTML(value);
          hasImage = html.includes("<img "); // only toHTML can emit this tag
        } catch {}
      }
      const nodes = html ? deserialize(editor, html, hasImage) : [];
      if (
        hasImage ||
        nodes.some(
          (n) =>
            NodeApi.string(n) !== "" ||
            (!TextApi.isText(n) && (n.type === "hr" || n.type === "table")),
        )
      ) {
        editor.tf.insertFragment(nodes);
        return;
      }
      const text = data.getData("text/plain");
      if (!text) return;
      // The caret's marks (the leaf's, or what the user toggled, {} included) for every line:
      // insertBreak clears them, and the new line would take the split leaf's instead.
      const marks = editor.api.marks() ?? {};
      text.split(/\r\n|\r|\n/).forEach((line, i) => {
        if (i) editor.tf.insertBreak();
        if (line) {
          editor.marks = { ...marks };
          editor.tf.insertText(line);
        }
      });
    },
  },
}));

/** Links of the forms safeHref accepts only. */
export const linkPlugin = LinkPlugin.configure({
  render: { as: "a" },
  options: { allowedSchemes: ["http", "https", "mailto"], isUrl: (u: string) => !!safeHref(u) },
});

/** ⌘K's selection marked while its popover has focus (Editor's `held` decoration); never saved. */
export const HeldPlugin = createPlatePlugin({
  key: "held",
  node: { isLeaf: true, props: { className: "bg-border" } },
});

export const FontSizePlugin = createPlatePlugin({
  key: "fontSize",
  node: { isLeaf: true },
  render: {
    node: ({ children, leaf }) =>
      React.createElement(
        "span",
        { style: { fontSize: (leaf as Record<string, unknown>).fontSize as string } },
        children,
      ),
  },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validStyle: { fontSize: "*" } }],
        parse: ({ element }) => ({ fontSize: element.style.fontSize }),
      },
    },
  },
});

export const FontFamilyPlugin = createPlatePlugin({
  key: "fontFamily",
  node: { isLeaf: true },
  render: {
    node: ({ children, leaf }) =>
      React.createElement(
        "span",
        { style: { fontFamily: (leaf as Record<string, unknown>).fontFamily as string } },
        children,
      ),
  },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validStyle: { fontFamily: "*" } }],
        parse: ({ element }) => ({ fontFamily: element.style.fontFamily }),
      },
    },
  },
});

export const FontColorPlugin = createPlatePlugin({
  key: "color",
  node: { isLeaf: true },
  render: {
    node: ({ children, leaf }) =>
      React.createElement(
        "span",
        { style: { color: (leaf as Record<string, unknown>).color as string } },
        children,
      ),
  },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validStyle: { color: "*" } }],
        parse: ({ element }) => ({ color: element.style.color }),
      },
    },
  },
});

export const BackgroundColorPlugin = createPlatePlugin({
  key: "backgroundColor",
  node: { isLeaf: true },
  render: {
    node: ({ children, leaf }) =>
      React.createElement(
        "span",
        {
          style: {
            backgroundColor: (leaf as Record<string, unknown>).backgroundColor as string,
          },
        },
        children,
      ),
  },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validStyle: { backgroundColor: "*" } }],
        parse: ({ element }) => ({ backgroundColor: element.style.backgroundColor }),
      },
    },
  },
});

function blockStyleProps(element?: Record<string, unknown>) {
  if (!element) return undefined;
  const style: React.CSSProperties = {};
  if (element.align === "center" || element.align === "right" || element.align === "left") {
    style.textAlign = element.align;
  }
  if (typeof element.indent === "number" && element.indent > 0) {
    style.marginLeft = `${Math.min(8, element.indent) * 24}px`;
  }
  return Object.keys(style).length > 0 ? { style } : undefined;
}

function parseBlockStyle(element: HTMLElement) {
  const out: Record<string, unknown> = {};
  const align = element.style.textAlign.trim().toLowerCase();
  if (align === "center" || align === "right") out.align = align;
  const m = element.style.marginLeft.trim().match(/^(\d+(?:\.\d+)?)px$/i);
  if (m) {
    const steps = Math.min(8, Math.max(0, Math.round(Number(m[1]) / 24)));
    if (steps > 0) out.indent = steps;
  }
  return out;
}

export const ParagraphFormatPlugin = ParagraphPlugin.configure({
  node: {
    props: ({ element }) => blockStyleProps(element as Record<string, unknown>),
  },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validNodeName: ["P", "DIV"] }],
        parse: ({ element }) => ({ type: "p", ...parseBlockStyle(element) }),
      },
    },
  },
});

export const BlockStyleInjectPlugin = createPlatePlugin({
  key: "blockStyle",
  inject: {
    targetPlugins: ["blockquote", "ul", "ol"],
    nodeProps: {
      transformProps: ({ element }) => blockStyleProps(element as Record<string, unknown>),
    },
  },
});

export const HrPlugin = createPlatePlugin({
  key: "hr",
  node: { isElement: true, isVoid: true },
  render: {
    node: ({ attributes, children }) =>
      React.createElement(
        "div",
        { ...attributes, contentEditable: false, className: "my-2 select-none" },
        React.createElement("hr", { className: "border-t border-border" }),
        children,
      ),
  },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validNodeName: "HR" }],
        parse: () => ({ type: "hr", children: [{ text: "" }] }),
      },
    },
  },
});

export const TablePlugin = createPlatePlugin({
  key: "table",
  node: { isElement: true },
  render: {
    node: ({ attributes, children }) =>
      React.createElement(
        "table",
        { ...attributes, className: "my-2 w-full border-collapse text-sm" },
        React.createElement("tbody", null, children),
      ),
  },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validNodeName: "TABLE" }],
        parse: () => ({ type: "table" }),
      },
    },
  },
});

export const TableRowPlugin = createPlatePlugin({
  key: "tr",
  node: { isElement: true },
  render: {
    node: ({ attributes, children }) => React.createElement("tr", attributes, children),
  },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validNodeName: "TR" }],
        parse: () => ({ type: "tr" }),
      },
    },
  },
});

export const TableCellPlugin = createPlatePlugin({
  key: "td",
  node: { isElement: true },
  render: {
    node: ({ attributes, children }) =>
      React.createElement(
        "td",
        { ...attributes, className: "border border-border px-2.5 py-1.5 align-top min-w-[60px]" },
        children,
      ),
  },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validNodeName: "TD" }],
        parse: () => ({ type: "td" }),
      },
    },
  },
});

export const TableHeaderCellPlugin = createPlatePlugin({
  key: "th",
  node: { isElement: true },
  render: {
    node: ({ attributes, children }) =>
      React.createElement(
        "th",
        {
          ...attributes,
          className:
            "border border-border bg-muted/40 px-2.5 py-1.5 text-left font-medium align-top min-w-[60px]",
        },
        children,
      ),
  },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validNodeName: "TH" }],
        parse: () => ({ type: "th" }),
      },
    },
  },
});

/** The draft's images as data: URLs by Content-ID (Go's ComposeState.Images), for DraftImagePlugin. */
export const DraftImages = createContext<Record<string, string>>({});

/** A draft image (`url` its cid: or legacy data:): shown from DraftImages; one not there yet shows as an empty box. */
function DraftImageElement(props: PlateElementProps) {
  const images = useContext(DraftImages);
  const raw = String(props.element.url ?? "");
  const url = raw.startsWith("cid:")
    ? images[raw.slice("cid:".length)]
    : IMAGE_SRC.test(raw)
      ? raw
      : undefined;
  return React.createElement(
    PlateElement,
    props,
    url
      ? React.createElement("img", {
          src: url,
          alt: "",
          contentEditable: false,
          className: "max-w-full select-none",
        })
      : React.createElement("span", {
          contentEditable: false,
          className: "block h-16 w-24 rounded-md bg-muted",
        }),
    props.children,
  );
}

/** An image in the body: an <img> whose src is CID_SRC, a void block. */
export const DraftImagePlugin = createPlatePlugin({
  key: "img",
  node: { isElement: true, isVoid: true, component: DraftImageElement },
  parsers: {
    html: {
      deserializer: {
        rules: [{ validNodeName: "IMG" }],
        parse: ({ element }) => {
          const url = element.getAttribute("src") ?? "";
          return CID_SRC.test(url) ? { type: "img", url } : undefined;
        },
      },
    },
  },
});

/**
 * The compose page formats: paragraph (core), bold, italic, underline, strikethrough,
 * font size, font family, text color, background highlight, alignment/indent, divider,
 * tables, link, bulleted and numbered list (list-classic ul/ol/li/lic), block quote,
 * and the draft's images.
 */
export const plugins: AnyPluginConfig[] = [
  BoldPlugin,
  ItalicPlugin,
  UnderlinePlugin,
  StrikethroughPlugin,
  FontSizePlugin,
  FontFamilyPlugin,
  FontColorPlugin,
  BackgroundColorPlugin,
  ParagraphFormatPlugin,
  BlockStyleInjectPlugin,
  HrPlugin,
  TablePlugin,
  TableRowPlugin,
  TableCellPlugin,
  TableHeaderCellPlugin,
  linkPlugin,
  ListPlugin.configurePlugin(TaskListPlugin, { enabled: false }),
  BlockquotePlugin,
  DraftImagePlugin,
  SafePastePlugin,
  HeldPlugin,
];
