import { defineConfig } from "vitepress";

const isGitHubPages = process.env.GITHUB_ACTIONS === "true";
const siteBase = isGitHubPages ? "/rookhold/" : "/";
const siteOrigin = isGitHubPages
  ? "https://sambai-dev.github.io/rookhold"
  : "https://rookhold.pages.dev";

export default defineConfig({
  title: "Rookhold",
  description: "Run short-lived Python, Node, and Bash code with hard limits and verifiable receipts.",
  lang: "en-US",
  base: siteBase,
  cleanUrls: true,
  lastUpdated: true,
  appearance: false,
  sitemap: { hostname: `${siteOrigin}/` },
  head: [
    ["meta", { name: "theme-color", content: "#12171e" }],
    ["link", { rel: "icon", type: "image/svg+xml", href: `${siteBase}rook.svg` }],
    ["meta", { property: "og:type", content: "website" }],
    ["meta", { property: "og:title", content: "Rookhold" }],
    ["meta", { property: "og:description", content: "Run short-lived code with hard limits—and keep a receipt." }],
    ["meta", { property: "og:image", content: `${siteOrigin}/social-card.png` }],
    ["meta", { property: "og:url", content: `${siteOrigin}/` }],
    ["meta", { name: "twitter:card", content: "summary_large_image" }],
  ],
  themeConfig: {
    logo: "/rook.svg",
    search: { provider: "local" },
    nav: [
      { text: "Get started", link: "/getting-started/quickstart" },
      { text: "CLI", link: "/use/cli" },
      { text: "MCP", link: "/use/mcp" },
      { text: "Security", link: "/security-boundary" },
      { text: "Deploy", link: "/deployment" },
      { text: "Try locally", link: "/#try" },
    ],
    sidebar: {
      "/getting-started/": [
        {
          text: "Getting started",
          items: [
            { text: "Quickstart", link: "/getting-started/quickstart" },
            { text: "Installation", link: "/getting-started/installation" },
            { text: "How Rookhold compares", link: "/compare" },
            { text: "First secure Linux deployment", link: "/getting-started/first-secure-deployment" },
          ],
        },
      ],
      "/use/": [
        {
          text: "Use Rookhold",
          items: [
            { text: "CLI", link: "/use/cli" },
            { text: "Python", link: "/use/python" },
            { text: "TypeScript", link: "/use/typescript" },
            { text: "MCP", link: "/use/mcp" },
            { text: "Recipes", link: "/use/recipes" },
          ],
        },
      ],
      "/understand/": [
        {
          text: "Understand Rookhold",
          items: [
            { text: "Architecture", link: "/architecture" },
            { text: "Execution model", link: "/understand/execution-model" },
            { text: "Limits", link: "/understand/limits" },
            { text: "Receipts", link: "/understand/receipts" },
            { text: "Isolation levels", link: "/understand/isolation" },
            { text: "Threat model", link: "/understand/threat-model" },
          ],
        },
      ],
      "/": [
        {
          text: "Operate Rookhold",
          items: [
            { text: "Configuration and deployment", link: "/deployment" },
            { text: "Operations", link: "/operations" },
            { text: "Upgrades", link: "/upgrading" },
            { text: "Observability", link: "/observability" },
            { text: "Troubleshooting", link: "/troubleshooting" },
            { text: "Compatibility", link: "/compatibility" },
            { text: "Projects using Rookhold", link: "/projects" },
          ],
        },
        {
          text: "Contribute",
          items: [
            { text: "Contribution tiers", link: "/contributing" },
            { text: "Runtime packs", link: "/runtime-packs" },
            { text: "Integrations", link: "/integrations" },
            { text: "Feedback", link: "/feedback" },
          ],
        },
      ],
    },
    socialLinks: [{ icon: "github", link: "https://github.com/sambai-dev/rookhold" }],
    editLink: { pattern: "https://github.com/sambai-dev/rookhold/edit/main/docs/:path" },
    footer: { message: "Short jobs. Hard limits. Receipts.", copyright: "Released under the MIT License." },
  },
});
