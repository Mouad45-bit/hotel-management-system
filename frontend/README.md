HMS Frontend
=================================

Frontend web application for the Hotel Management System.

Stack
--------

- Next.js
- TypeScript
- Tailwind CSS
- Headless UI
- Heroicons
- Zod
- clsx

UI decision
--------

The project does not use Catalyst UI Kit.

The frontend uses a free official Tailwind-based stack:

- Tailwind CSS for styling
- Headless UI for accessible interactive components
- Heroicons for icons
- HMS custom components for project-specific design

Main folders
--------

```
src/app
src/components/hms
src/components/layout
src/components/rooms
src/lib
src/services
src/types
src/schemas
```

Environment
-----------

Create a local `.env.local` file:

```
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080
```

The frontend must call backend services through the API Gateway.

Run locally
-----------

```
npm install
npm run dev
```

Application URL:

```
http://localhost:3000
```

Build
-----

```
npm run build
```

Current module
--------------

The first demonstrable module is:

```
Rooms / Chambres
```

Frontend route:

```
/rooms
```
