// See https://observablehq.com/framework/config for documentation.

export default {
  // The project’s title; used in the sidebar and webpage titles.
  title: "GHSA Research",

  header: "<i style='position: relative; z-index: 99; float: right'><a href='https://github.com/bburky/ghsa-research'>View source ⬈</a></i>",

  // The pages and sections in the sidebar. If you don’t specify this option,
  // all pages will be listed in alphabetical order. Listing pages explicitly
  // lets you organize them into sections and have unlisted pages.
  // pages: [
  //   {
  //     name: "Examples",
  //     pages: [
  //       {name: "Dashboard", path: "/example-dashboard"},
  //       {name: "Report", path: "/example-report"}
  //     ]
  //   }
  // ],

  // Some additional configuration options and their defaults:
  // theme: "default", // try "light", "dark", "slate", etc.
  // header: "", // what to show in the header (HTML)
  // footer: "Built with Observable.", // what to show in the footer (HTML)
  // toc: true, // whether to show the table of contents
  // pager: true, // whether to show previous & next links in the footer
  // root: "docs", // path to the source root for preview
  // output: "dist", // path to the output root for build
  // search: true, // activate search

  interpreters: {
    ".sh": [], // treat .sh more like .exe: use the shebang line inside the script
  }
};
