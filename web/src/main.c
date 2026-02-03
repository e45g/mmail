#include <linux/limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "auth.h"
#include "eml_parser.h"
#include "db.h"
#include "routes.h"
#include "server.h"
#include "utils.h"

#include "cxc/inbox.h"
#include "cxc/login.h"
#include "cxc/register.h"
#include "cxc/email_view.h"

#define DOMAIN "example.com"

// Helper to get session or redirect
static session_user_t *require_auth(int client_fd, http_req_t *req) {
    session_user_t *user = get_session_user(req);
    if (!user) {
        send_redirect(client_fd, "/login");
        return NULL;
    }
    return user;
}

// GET /login
void handle_login_page(int client_fd, http_req_t *req __attribute__((unused))) {
    LoginProps props = {
        .error_message = "",
        .domain = DOMAIN
    };

    char *html = render_login(&props);
    send_string(client_fd, html);
    free(html);
}

// POST /login
void handle_login_submit(int client_fd, http_req_t *req) {
    int field_count = 0;
    form_field_t *fields = parse_form_data(req->body, &field_count);

    char *email = get_form_field(fields, field_count, "email");
    char *password = get_form_field(fields, field_count, "password");

    if (!email || !password || strlen(email) == 0 || strlen(password) == 0) {
        LoginProps props = {
            .error_message = "Email and password are required",
            .domain = DOMAIN
        };
        char *html = render_login(&props);
        send_string(client_fd, html);
        free(html);
        free_form_fields(fields, field_count);
        return;
    }

    session_user_t *user = authenticate_user(email, password);
    if (!user) {
        LoginProps props = {
            .error_message = "Invalid email or password",
            .domain = DOMAIN
        };
        char *html = render_login(&props);
        send_string(client_fd, html);
        free(html);
        free_form_fields(fields, field_count);
        return;
    }

    char *token = create_session(user->user_id);
    free(user);
    free_form_fields(fields, field_count);

    if (!token) {
        LoginProps props = {
            .error_message = "Failed to create session",
            .domain = DOMAIN
        };
        char *html = render_login(&props);
        send_string(client_fd, html);
        free(html);
        return;
    }

    char cookie[256];
    snprintf(cookie, sizeof(cookie),
        "session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400",
        token);
    free(token);

    send_redirect_with_cookie(client_fd, "/", cookie);
}

// GET /register
void handle_register_page(int client_fd, http_req_t *req __attribute__((unused))) {
    RegisterProps props = {
        .error_message = "",
        .domain = DOMAIN
    };

    char *html = render_register(&props);
    send_string(client_fd, html);
    free(html);
}

// POST /register
void handle_register_submit(int client_fd, http_req_t *req) {
    int field_count = 0;
    form_field_t *fields = parse_form_data(req->body, &field_count);

    char *username = get_form_field(fields, field_count, "username");
    char *domain = get_form_field(fields, field_count, "domain");
    char *password = get_form_field(fields, field_count, "password");
    char *password_confirm = get_form_field(fields, field_count, "password_confirm");

    // Use configured domain if not provided
    if (!domain || strlen(domain) == 0) {
        domain = DOMAIN;
    }

    // Validation
    if (!username || strlen(username) == 0) {
        RegisterProps props = { .error_message = "Username is required", .domain = DOMAIN };
        char *html = render_register(&props);
        send_string(client_fd, html);
        free(html);
        free_form_fields(fields, field_count);
        return;
    }

    if (!password || strlen(password) < 6) {
        RegisterProps props = { .error_message = "Password must be at least 6 characters", .domain = DOMAIN };
        char *html = render_register(&props);
        send_string(client_fd, html);
        free(html);
        free_form_fields(fields, field_count);
        return;
    }

    if (!password_confirm || strcmp(password, password_confirm) != 0) {
        RegisterProps props = { .error_message = "Passwords do not match", .domain = DOMAIN };
        char *html = render_register(&props);
        send_string(client_fd, html);
        free(html);
        free_form_fields(fields, field_count);
        return;
    }

    // Check username format (alphanumeric, dots, underscores)
    for (size_t i = 0; i < strlen(username); i++) {
        char c = username[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) {
            RegisterProps props = { .error_message = "Username can only contain letters, numbers, dots, underscores, and hyphens", .domain = DOMAIN };
            char *html = render_register(&props);
            send_string(client_fd, html);
            free(html);
            free_form_fields(fields, field_count);
            return;
        }
    }

    // Create user
    int result = create_user(username, domain, password);
    free_form_fields(fields, field_count);

    if (result != 0) {
        RegisterProps props = { .error_message = "Username already exists or registration failed", .domain = DOMAIN };
        char *html = render_register(&props);
        send_string(client_fd, html);
        free(html);
        return;
    }

    // Registration successful, redirect to login
    send_redirect(client_fd, "/login");
}

// GET /logout
void handle_logout(int client_fd, http_req_t *req) {
    char *token = get_cookie(req, "session");
    if (token) {
        delete_session(token);
        free(token);
    }

    // Clear cookie and redirect
    send_redirect_with_cookie(client_fd, "/login",
        "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
}

// GET / (inbox)
void handle_inbox(int client_fd, http_req_t *req) {
    session_user_t *user = require_auth(client_fd, req);
    if (!user) return;

    const char *query =
        "SELECT e.id, e.sender_address, e.subject, e.snippet, "
        "TO_CHAR(e.received_at, 'Mon DD, HH24:MI'), ui.is_read "
        "FROM emails e "
        "JOIN user_inbox ui ON e.id = ui.email_id "
        "JOIN users u ON ui.user_id = u.id "
        "WHERE u.full_address = $1 AND ui.deleted_at IS NULL "
        "ORDER BY e.received_at DESC";

    const char *params[] = {user->full_address};
    db_result_t *res = db_prepare(query, params, 1);

    InboxProps props = {
        .username = user->username,
        .full_address = user->full_address,
        .emails = res
    };

    char *html = render_inbox(&props);
    send_string(client_fd, html);

    free(html);
    free(user);
    if (res) db_free(res);
}

// GET /email/*
void handle_email_view(int client_fd, http_req_t *req) {
    session_user_t *user = require_auth(client_fd, req);
    if (!user) return;

    // Get email ID from wildcard
    const char *email_id = req->wildcards[0];
    if (!email_id || strlen(email_id) == 0) {
        send_redirect(client_fd, "/");
        free(user);
        return;
    }

    // Get email details and verify ownership
    const char *query =
        "SELECT e.file_path, e.subject "
        "FROM emails e "
        "JOIN user_inbox ui ON e.id = ui.email_id "
        "JOIN users u ON ui.user_id = u.id "
        "WHERE e.id = $1 AND u.full_address = $2 AND ui.deleted_at IS NULL";

    const char *params[] = {email_id, user->full_address};
    db_result_t *res = db_prepare(query, params, 2);

    if (!res || res->num_rows == 0) {
        send_redirect(client_fd, "/");
        free(user);
        if (res) db_free(res);
        return;
    }

    const char *db_file_path = res->rows[0][0];

    // Build path - check if running from project root or web/ directory
    char file_path[512];
    struct stat st;
    if (stat("emails", &st) == 0 && S_ISDIR(st.st_mode)) {
        // Running from project root (unified binary)
        snprintf(file_path, sizeof(file_path), "%s", db_file_path);
    } else {
        // Running from web/ directory (standalone)
        snprintf(file_path, sizeof(file_path), "../%s", db_file_path);
    }

    // Mark as read
    const char *mark_read_query =
        "UPDATE user_inbox SET is_read = TRUE "
        "WHERE email_id = $1 AND user_id = (SELECT id FROM users WHERE full_address = $2)";
    const char *mark_params[] = {email_id, user->full_address};
    db_result_t *mark_res = db_prepare(mark_read_query, mark_params, 2);
    if (mark_res) db_free(mark_res);

    // Parse email file
    parsed_email_t *email = parse_eml_file(file_path);
    db_free(res);

    if (!email) {
        send_redirect(client_fd, "/");
        free(user);
        return;
    }

    // Escape all fields for HTML display to prevent XSS
    char *escaped_from = html_escape(email->from);
    char *escaped_to = html_escape(email->to);
    char *escaped_subject = html_escape(email->subject);
    char *escaped_body = html_escape(email->body);

    EmailViewProps props = {
        .full_address = user->full_address,
        .email_id = (char *)email_id,
        .from = escaped_from ? escaped_from : email->from,
        .to = escaped_to ? escaped_to : email->to,
        .subject = escaped_subject ? escaped_subject : email->subject,
        .date = email->date,
        .body = escaped_body ? escaped_body : email->body
    };

    char *html = render_email_view(&props);
    send_string(client_fd, html);

    free(html);
    free(user);
    if (escaped_from) free(escaped_from);
    if (escaped_to) free(escaped_to);
    if (escaped_subject) free(escaped_subject);
    if (escaped_body) free(escaped_body);
    free_parsed_email(email);
}

// Static file handler for CSS
void handle_static(int client_fd, http_req_t *req) {
    serve_file(client_fd, req->path);
}

void handle_robots(int client_fd, http_req_t *req __attribute__((unused))) {
    send_plain(client_fd, "User-agent: *\nAllow: /");
}

void handle_log(int client_fd, http_req_t *req __attribute__((unused))) {
    serve_file(client_fd, "../log.txt");
}

void load_routes() {
    const char *sub = get_web_subdomain();

    // Static files
    add_route("GET", "/robots.txt", sub, handle_robots);
    add_route("GET", "/css/*", sub, handle_static);

    // Auth routes
    add_route("GET", "/login", sub, handle_login_page);
    add_route("POST", "/login", sub, handle_login_submit);
    add_route("GET", "/register", sub, handle_register_page);
    add_route("POST", "/register", sub, handle_register_submit);
    add_route("GET", "/logout", sub, handle_logout);

    // Protected routes
    add_route("GET", "/", sub, handle_inbox);
    add_route("GET", "/email/*", sub, handle_email_view);

    // Debug
    add_route("GET", "/log", sub, handle_log);
}

// Standalone entry point (used when building web server separately)
#ifndef UNIFIED_BUILD
int main(void) {
    set_log_file("web");
    int result = load_env(".env");
    if(result != 0) LOG("Invalid env file.");

    const char *db_password = get_db_password();
    if(db_init("localhost", "mmail", "mmail_user", db_password) != 0) {
        LOG("Failed to init postgresql");
    }

    server_run(load_routes);

    return 0;
}
#endif
