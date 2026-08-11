import starlight from "@astrojs/starlight";
// @ts-check
import { defineConfig } from "astro/config";

// https://astro.build/config
export default defineConfig({
  site: process.env.DOCS_SITE ?? "https://example.com",
  integrations: [
    starlight({
      title: "My Docs",
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/withastro/starlight" }],
      sidebar: [
        {
          label: "Guides",
          items: [
            // Each item here is one entry in the navigation menu.
            { label: "Example Guide", slug: "guides/example" },
          ],
        },
        {
          label: "Image Generation",
          items: [
            { label: "Overview", slug: "image-generation/overview" },
            { label: "OpenAI Images", slug: "image-generation/openai" },
            { label: "OpenRouter Images", slug: "image-generation/openrouter" },
            { label: "Gemini Images", slug: "image-generation/gemini" },
            { label: "ComfyUI", slug: "image-generation/comfyui" },
            { label: "Security and Budgets", slug: "image-generation/security-and-budgets" },
            { label: "Jobs and Artifacts", slug: "image-generation/jobs-and-artifacts" },
            { label: "Remote Client", slug: "image-generation/remote-client" },
            { label: "Troubleshooting", slug: "image-generation/troubleshooting" },
          ],
        },
        {
          label: "Reference",
          items: [{ autogenerate: { directory: "reference" } }],
        },
      ],
    }),
  ],
});
