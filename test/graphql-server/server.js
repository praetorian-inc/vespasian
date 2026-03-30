const { ApolloServer } = require("@apollo/server");
const { expressMiddleware } = require("@apollo/server/express4");
const express = require("express");
const http = require("http");

const typeDefs = `#graphql
  type Query {
    users(limit: Int, offset: Int): [User!]!
    user(id: ID!): User
    posts(authorId: ID): [Post!]!
    post(id: ID!): Post
    search(query: String!, type: SearchType): SearchResult!
    serverInfo: ServerInfo!
  }

  type Mutation {
    createUser(input: CreateUserInput!): User!
    updateUser(id: ID!, input: UpdateUserInput!): User!
    deleteUser(id: ID!): Boolean!
    createPost(input: CreatePostInput!): Post!
    likePost(id: ID!): Post!
  }

  type Subscription {
    postCreated: Post!
  }

  type User {
    id: ID!
    name: String!
    email: String!
    role: Role!
    posts: [Post!]!
    createdAt: String!
  }

  type Post {
    id: ID!
    title: String!
    content: String!
    author: User!
    tags: [String!]!
    likes: Int!
    published: Boolean!
    createdAt: String!
  }

  type SearchResult {
    users: [User!]!
    posts: [Post!]!
    totalCount: Int!
  }

  type ServerInfo {
    version: String!
    uptime: Float!
  }

  input CreateUserInput {
    name: String!
    email: String!
    role: Role
  }

  input UpdateUserInput {
    name: String
    email: String
    role: Role
  }

  input CreatePostInput {
    title: String!
    content: String!
    authorId: ID!
    tags: [String!]
  }

  enum Role {
    ADMIN
    EDITOR
    VIEWER
  }

  enum SearchType {
    USER
    POST
  }

  union SearchItem = User | Post
`;

// Sample data
const users = [
  { id: "1", name: "Alice Johnson", email: "alice@example.com", role: "ADMIN", createdAt: "2026-01-15T10:00:00Z" },
  { id: "2", name: "Bob Smith", email: "bob@example.com", role: "EDITOR", createdAt: "2026-02-01T12:00:00Z" },
  { id: "3", name: "Carol White", email: "carol@example.com", role: "VIEWER", createdAt: "2026-03-10T08:30:00Z" },
];

const posts = [
  { id: "10", title: "Getting Started with GraphQL", content: "GraphQL is a query language for APIs that gives clients the power to ask for exactly what they need.", authorId: "1", tags: ["graphql", "tutorial"], likes: 42, published: true, createdAt: "2026-01-20T14:00:00Z" },
  { id: "11", title: "Advanced Mutations", content: "Mutations allow you to modify server-side data and return the updated result.", authorId: "1", tags: ["graphql", "advanced"], likes: 18, published: true, createdAt: "2026-02-05T09:00:00Z" },
  { id: "12", title: "Draft Post", content: "Work in progress...", authorId: "2", tags: [], likes: 0, published: false, createdAt: "2026-03-01T16:00:00Z" },
  { id: "13", title: "Security Best Practices", content: "Always validate input, use parameterized queries, and implement proper authentication.", authorId: "2", tags: ["security", "best-practices"], likes: 73, published: true, createdAt: "2026-03-15T11:00:00Z" },
];

let nextUserId = 4;
let nextPostId = 14;

const resolvers = {
  Query: {
    users: (_, { limit, offset }) => {
      let result = [...users];
      if (offset) result = result.slice(offset);
      if (limit) result = result.slice(0, limit);
      return result;
    },
    user: (_, { id }) => users.find((u) => u.id === id) || null,
    posts: (_, { authorId }) => {
      if (authorId) return posts.filter((p) => p.authorId === authorId);
      return [...posts];
    },
    post: (_, { id }) => posts.find((p) => p.id === id) || null,
    search: (_, { query, type }) => {
      const q = query.toLowerCase();
      const matchedUsers = type === "POST" ? [] : users.filter((u) => u.name.toLowerCase().includes(q));
      const matchedPosts = type === "USER" ? [] : posts.filter((p) => p.title.toLowerCase().includes(q) || p.content.toLowerCase().includes(q));
      return { users: matchedUsers, posts: matchedPosts, totalCount: matchedUsers.length + matchedPosts.length };
    },
    serverInfo: () => ({ version: "1.0.0", uptime: process.uptime() }),
  },
  Mutation: {
    createUser: (_, { input }) => {
      const user = { id: String(nextUserId++), ...input, role: input.role || "VIEWER", createdAt: new Date().toISOString() };
      users.push(user);
      return user;
    },
    updateUser: (_, { id, input }) => {
      const user = users.find((u) => u.id === id);
      if (!user) throw new Error("User not found");
      Object.assign(user, input);
      return user;
    },
    deleteUser: (_, { id }) => {
      const idx = users.findIndex((u) => u.id === id);
      if (idx === -1) return false;
      users.splice(idx, 1);
      return true;
    },
    createPost: (_, { input }) => {
      const post = { id: String(nextPostId++), ...input, likes: 0, published: false, createdAt: new Date().toISOString() };
      posts.push(post);
      return post;
    },
    likePost: (_, { id }) => {
      const post = posts.find((p) => p.id === id);
      if (!post) throw new Error("Post not found");
      post.likes++;
      return post;
    },
  },
  User: {
    posts: (user) => posts.filter((p) => p.authorId === user.id),
  },
  Post: {
    author: (post) => users.find((u) => u.id === post.authorId),
  },
};

// ─── HTML Pages ─────────────────────────────────────────────────────────────

const layout = (title, body) => `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>${title} - BlogQL</title>
<style>
  body { font-family: sans-serif; max-width: 800px; margin: 2em auto; padding: 0 1em; }
  nav { background: #333; padding: 0.5em 1em; margin-bottom: 1.5em; border-radius: 4px; }
  nav a { color: #fff; text-decoration: none; margin-right: 1.5em; }
  nav a:hover { text-decoration: underline; }
  .card { border: 1px solid #ddd; padding: 1em; margin-bottom: 1em; border-radius: 4px; }
  .tag { background: #e0e0e0; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; margin-right: 4px; }
  .meta { color: #666; font-size: 0.9em; }
  form { margin-top: 1em; }
  input, select, textarea { display: block; margin: 0.3em 0 1em 0; padding: 0.4em; width: 300px; }
  button { padding: 0.5em 1.5em; background: #333; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
  #results { margin-top: 1em; }
</style>
<script>
  function esc(s) { var d = document.createElement('div'); d.appendChild(document.createTextNode(s)); return d.innerHTML; }
</script>
</head>
<body>
<nav>
  <a href="/">Home</a>
  <a href="/users">Users</a>
  <a href="/posts">Posts</a>
  <a href="/search">Search</a>
  <a href="/create">Create</a>
</nav>
${body}
</body></html>`;

const pages = {
  "/": layout("Home", `
    <h1>BlogQL</h1>
    <p>A sample blog powered by GraphQL.</p>
    <div id="info"></div>
    <h2>Recent Posts</h2>
    <div id="recent"></div>
    <script>
      fetch("/graphql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{ serverInfo { version uptime } }" })
      }).then(r => r.json()).then(d => {
        const info = d.data.serverInfo;
        document.getElementById("info").innerHTML =
          '<p class="meta">Server v' + esc(info.version) + ' | uptime: ' + info.uptime.toFixed(1) + 's</p>';
      });

      fetch("/graphql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: "query RecentPosts { posts { id title author { name } likes tags published createdAt } }"
        })
      }).then(r => r.json()).then(d => {
        document.getElementById("recent").innerHTML = d.data.posts
          .filter(p => p.published)
          .map(p => '<div class="card">' +
            '<h3><a href="/posts/' + esc(p.id) + '">' + esc(p.title) + '</a></h3>' +
            '<p class="meta">by ' + esc(p.author.name) + ' | ' + p.likes + ' likes | ' + esc(p.createdAt.slice(0,10)) + '</p>' +
            '<p>' + p.tags.map(t => '<span class="tag">' + esc(t) + '</span>').join('') + '</p>' +
          '</div>').join('');
      });
    </script>
  `),

  "/users": layout("Users", `
    <h1>Users</h1>
    <div id="users"></div>
    <script>
      fetch("/graphql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: "query AllUsers($limit: Int) { users(limit: $limit) { id name email role createdAt posts { id title } } }",
          variables: { limit: 20 }
        })
      }).then(r => r.json()).then(d => {
        document.getElementById("users").innerHTML = d.data.users.map(u =>
          '<div class="card">' +
            '<h3><a href="/users/' + esc(u.id) + '">' + esc(u.name) + '</a></h3>' +
            '<p class="meta">' + esc(u.email) + ' | ' + esc(u.role) + ' | joined ' + esc(u.createdAt.slice(0,10)) + '</p>' +
            '<p>' + u.posts.length + ' posts: ' + u.posts.map(p => '<a href="/posts/' + esc(p.id) + '">' + esc(p.title) + '</a>').join(', ') + '</p>' +
          '</div>').join('');
      });
    </script>
  `),

  "/posts": layout("Posts", `
    <h1>All Posts</h1>
    <div id="posts"></div>
    <script>
      fetch("/graphql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: "query AllPosts { posts { id title content author { id name } tags likes published createdAt } }"
        })
      }).then(r => r.json()).then(d => {
        document.getElementById("posts").innerHTML = d.data.posts.map(p =>
          '<div class="card">' +
            '<h3><a href="/posts/' + esc(p.id) + '">' + esc(p.title) + '</a>' + (p.published ? '' : ' <em>(draft)</em>') + '</h3>' +
            '<p>' + esc(p.content.slice(0, 120)) + '</p>' +
            '<p class="meta">by <a href="/users/' + esc(p.author.id) + '">' + esc(p.author.name) + '</a> | ' + p.likes + ' likes</p>' +
            '<p>' + p.tags.map(t => '<span class="tag">' + esc(t) + '</span>').join('') + '</p>' +
          '</div>').join('');
      });
    </script>
  `),

  "/search": layout("Search", `
    <h1>Search</h1>
    <form id="searchForm">
      <input type="text" id="q" placeholder="Search posts and users..." value="graphql">
      <select id="type">
        <option value="">All</option>
        <option value="USER">Users only</option>
        <option value="POST">Posts only</option>
      </select>
      <button type="submit">Search</button>
    </form>
    <div id="results"></div>
    <script>
      document.getElementById("searchForm").addEventListener("submit", function(e) {
        e.preventDefault();
        const q = document.getElementById("q").value;
        const type = document.getElementById("type").value;
        const variables = { q: q };
        if (type) variables.type = type;

        fetch("/graphql", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            query: "query Search($q: String!, $type: SearchType) { search(query: $q, type: $type) { users { id name email } posts { id title } totalCount } }",
            variables: variables
          })
        }).then(r => r.json()).then(d => {
          const s = d.data.search;
          let html = '<p>Found ' + s.totalCount + ' results</p>';
          if (s.users.length) {
            html += '<h3>Users</h3>' + s.users.map(u =>
              '<div class="card"><a href="/users/' + esc(u.id) + '">' + esc(u.name) + '</a> - ' + esc(u.email) + '</div>'
            ).join('');
          }
          if (s.posts.length) {
            html += '<h3>Posts</h3>' + s.posts.map(p =>
              '<div class="card"><a href="/posts/' + esc(p.id) + '">' + esc(p.title) + '</a></div>'
            ).join('');
          }
          document.getElementById("results").innerHTML = html;
        });
      });
      // Auto-search on load
      document.getElementById("searchForm").dispatchEvent(new Event("submit"));
    </script>
  `),

  "/create": layout("Create Post", `
    <h1>Create Post</h1>
    <form id="createForm">
      <label>Title</label>
      <input type="text" id="title" value="My New Post">
      <label>Content</label>
      <textarea id="content" rows="4">This is a test post created via the web UI.</textarea>
      <label>Author</label>
      <select id="authorId"></select>
      <label>Tags (comma-separated)</label>
      <input type="text" id="tags" value="test, demo">
      <button type="submit">Create Post</button>
    </form>
    <div id="result"></div>
    <script>
      // Load authors
      fetch("/graphql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{ users { id name } }" })
      }).then(r => r.json()).then(d => {
        const sel = document.getElementById("authorId");
        d.data.users.forEach(u => {
          const opt = document.createElement("option");
          opt.value = u.id; opt.textContent = u.name;
          sel.appendChild(opt);
        });
      });

      document.getElementById("createForm").addEventListener("submit", function(e) {
        e.preventDefault();
        const tags = document.getElementById("tags").value.split(",").map(t => t.trim()).filter(Boolean);
        fetch("/graphql", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            query: "mutation CreatePost($input: CreatePostInput!) { createPost(input: $input) { id title content tags published createdAt } }",
            variables: {
              input: {
                title: document.getElementById("title").value,
                content: document.getElementById("content").value,
                authorId: document.getElementById("authorId").value,
                tags: tags
              }
            }
          })
        }).then(r => r.json()).then(d => {
          const p = d.data.createPost;
          document.getElementById("result").innerHTML =
            '<div class="card"><h3>Created: ' + esc(p.title) + '</h3><p>ID: ' + esc(p.id) + ' | Published: ' + p.published + '</p></div>';
        });
      });
    </script>
  `),
};

// Dynamic user detail page
function userPage(id) {
  return layout("User", `
    <h1>User Profile</h1>
    <div id="user"></div>
    <script>
      fetch("/graphql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: "query GetUser($id: ID!) { user(id: $id) { id name email role createdAt posts { id title likes published } } }",
          variables: { id: ${JSON.stringify(id)} }
        })
      }).then(r => r.json()).then(d => {
        const u = d.data.user;
        if (!u) { document.getElementById("user").innerHTML = "<p>User not found</p>"; return; }
        document.getElementById("user").innerHTML =
          '<div class="card"><h2>' + esc(u.name) + '</h2>' +
          '<p class="meta">' + esc(u.email) + ' | ' + esc(u.role) + ' | joined ' + esc(u.createdAt.slice(0,10)) + '</p>' +
          '<h3>Posts</h3>' +
          u.posts.map(p =>
            '<div class="card"><a href="/posts/' + esc(p.id) + '">' + esc(p.title) + '</a> | ' + p.likes + ' likes' +
            (p.published ? '' : ' (draft)') + '</div>'
          ).join('') + '</div>';
      });
    </script>
  `);
}

// Dynamic post detail page with like button
function postPage(id) {
  return layout("Post", `
    <div id="post"></div>
    <script>
      let postId = ${JSON.stringify(id)};
      function loadPost() {
        fetch("/graphql", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            query: "query GetPost($id: ID!) { post(id: $id) { id title content author { id name } tags likes published createdAt } }",
            variables: { id: postId }
          })
        }).then(r => r.json()).then(d => {
          const p = d.data.post;
          if (!p) { document.getElementById("post").innerHTML = "<p>Post not found</p>"; return; }
          document.getElementById("post").innerHTML =
            '<h1>' + esc(p.title) + '</h1>' +
            '<p class="meta">by <a href="/users/' + esc(p.author.id) + '">' + esc(p.author.name) + '</a> | ' +
            esc(p.createdAt.slice(0,10)) + (p.published ? '' : ' | <em>draft</em>') + '</p>' +
            '<p>' + esc(p.content) + '</p>' +
            '<p>' + p.tags.map(t => '<span class="tag">' + esc(t) + '</span>').join('') + '</p>' +
            '<p><button onclick="likePost()">\u2764 Like (' + p.likes + ')</button></p>';
        });
      }
      function likePost() {
        fetch("/graphql", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            query: "mutation LikePost($id: ID!) { likePost(id: $id) { id likes } }",
            variables: { id: postId }
          })
        }).then(r => r.json()).then(() => loadPost());
      }
      loadPost();
    </script>
  `);
}

// ─── Server Setup ───────────────────────────────────────────────────────────

const disableIntrospection = process.argv.includes("--no-introspection");

async function start() {
  const app = express();

  // HTML routes (before GraphQL middleware)
  app.get("/", (req, res) => res.send(pages["/"]));
  app.get("/users", (req, res) => res.send(pages["/users"]));
  app.get("/users/:id", (req, res) => res.send(userPage(req.params.id)));
  app.get("/posts", (req, res) => res.send(pages["/posts"]));
  app.get("/posts/:id", (req, res) => res.send(postPage(req.params.id)));
  app.get("/search", (req, res) => res.send(pages["/search"]));
  app.get("/create", (req, res) => res.send(pages["/create"]));

  // Apollo GraphQL
  const plugins = [];
  if (disableIntrospection) {
    console.log("Introspection: DISABLED");
  } else {
    console.log("Introspection: ENABLED");
  }

  const server = new ApolloServer({ typeDefs, resolvers, plugins, introspection: !disableIntrospection });
  await server.start();

  app.use("/graphql", express.json(), expressMiddleware(server));

  const httpServer = http.createServer(app);
  const port = parseInt(process.env.PORT, 10) || 4000;
  httpServer.listen(port, () => {
    console.log("Server ready at http://localhost:" + port + "/");
    console.log("GraphQL endpoint: http://localhost:" + port + "/graphql");
    console.log("\nPages:");
    console.log("  http://localhost:" + port + "/          (home + recent posts)");
    console.log("  http://localhost:" + port + "/users      (all users)");
    console.log("  http://localhost:" + port + "/users/1    (user detail)");
    console.log("  http://localhost:" + port + "/posts      (all posts)");
    console.log("  http://localhost:" + port + "/posts/10   (post detail + like)");
    console.log("  http://localhost:" + port + "/search     (search)");
    console.log("  http://localhost:" + port + "/create     (create post form)");
    console.log("\nVespasian:");
    console.log("  ./vespasian-test scan http://localhost:" + port + "/ --api-type graphql -v -o schema.graphql");
  });
}

start().catch(console.error);
