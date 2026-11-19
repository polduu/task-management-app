# Project Management App

Full-stack project management application (Trello/Jira style) built with Spring Boot and containerized for production. Designed to demonstrate enterprise backend patterns and DevOps practices.

---

## Tech Stack

### Backend
* **Java 17+ / Spring Boot**
* **Spring Data JPA (Hibernate) & PostgreSQL**
* **Spring Security & JWT** (Authentication & Authorization)
* **WebSockets** (Real-time updates)
* **Maven** (Dependency Management)

### Frontend
* React
* Nginx (Production static file server)

### DevOps & Infrastructure
* **Docker & Docker Compose** (Containerization)
* **GitHub Actions** (CI/CD pipelines for automated testing and builds)

---

## Project Structure

```text
project-management-app/
├── backend/          # Spring Boot REST API source code
├── frontend/         # Web user interface
├── compose.yml       # Multi-container orchestration
└── .github/          # CI/CD workflows
```

## Backend development

Run backend tests from the `backend` directory:

```bash
./mvnw clean test
```

When using VS Code, disable the Java extension's automatic build before running
Maven. Otherwise, its Eclipse compiler can overwrite Maven's generated
MapStruct classes in `backend/target`, causing `UserMapper` compilation or
Spring bean errors.

In `.vscode/settings.json`:

{
  "java.autobuild.enabled": false
}
