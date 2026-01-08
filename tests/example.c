#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME_LEN 64
#define MAX_USERS 16

#define LOG_INFO(fmt, ...) \
    printf("[INFO] " fmt "\n", ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
    fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

/* -------------------------------
 * Enum and Struct Definitions
 * ------------------------------- */

typedef enum {
    ROLE_GUEST = 0,
    ROLE_USER,
    ROLE_ADMIN
} UserRole;

typedef struct {
    int id;
    char name[MAX_NAME_LEN];
    UserRole role;
    int is_active;
} User;

/* -------------------------------
 * Global Variables
 * ------------------------------- */

static User *g_users[MAX_USERS];
static int g_user_count = 0;

/* -------------------------------
 * Utility Functions
 * ------------------------------- */

static const char *role_to_string(UserRole role) {
    switch (role) {
        case ROLE_GUEST: return "guest";
        case ROLE_USER:  return "user";
        case ROLE_ADMIN: return "admin";
        default:         return "unknown";
    }
}

static void print_user(const User *u) {
    if (!u) {
        LOG_ERROR("NULL user");
        return;
    }

    printf("User{id=%d, name='%s', role=%s, active=%d}\n",
           u->id,
           u->name,
           role_to_string(u->role),
           u->is_active);
}

/* -------------------------------
 * User Management
 * ------------------------------- */

static User *allocate_user(int id, const char *name, UserRole role) {
    User *u = (User *)malloc(sizeof(User));
    /* intentionally missing NULL check for demo */

    u->id = id;
    strcpy(u->name, name); /* unsafe on purpose (ast-grep demo) */
    u->role = role;
    u->is_active = 1;

    return u;
}

static int add_user(User *u) {
    if (g_user_count >= MAX_USERS) {
        LOG_ERROR("User limit reached");
        return -1;
    }

    g_users[g_user_count++] = u;
    return 0;
}

static User *find_user_by_id(int id) {
    for (int i = 0; i < g_user_count; i++) {
        if (g_users[i] && g_users[i]->id == id) {
            return g_users[i];
        }
    }
    return NULL;
}

static void deactivate_user(User *u) {
    if (u) {
        u->is_active = 0;
    }
}

static void delete_user(User *u) {
    if (!u) return;
    free(u);
}

/* -------------------------------
 * Demo Logic
 * ------------------------------- */

static void init_demo_users(void) {
    add_user(allocate_user(1, "alice", ROLE_ADMIN));
    add_user(allocate_user(2, "bob", ROLE_USER));
    add_user(allocate_user(3, "guest", ROLE_GUEST));
}

static void list_users(void) {
    LOG_INFO("Listing users (%d total)", g_user_count);

    for (int i = 0; i < g_user_count; i++) {
        print_user(g_users[i]);
    }
}

static void simulate_activity(void) {
    User *u = find_user_by_id(2);
    if (u) {
        LOG_INFO("Deactivating user id=2");
        deactivate_user(u);
    }
}

static void cleanup(void) {
    for (int i = 0; i < g_user_count; i++) {
        delete_user(g_users[i]);
        g_users[i] = NULL;
    }
    g_user_count = 0;
}

/* -------------------------------
 * Misc Code for Pattern Matching
 * ------------------------------- */

static int sum_array(int *arr, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}

static void pointer_demo(void) {
    int values[5] = {1, 2, 3, 4, 5};
    int *p = values;

    for (int i = 0; i < 5; i++) {
        printf("value[%d] = %d\n", i, *(p + i));
    }

    printf("sum = %d\n", sum_array(values, 5));
}

/* -------------------------------
 * Main
 * ------------------------------- */

int main(int argc, char **argv) {
    LOG_INFO("Program started");

    init_demo_users();
    list_users();

    simulate_activity();
    list_users();

    pointer_demo();

    cleanup();

    LOG_INFO("Program finished");
    return 0;
}