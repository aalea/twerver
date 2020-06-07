#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include "socket.h"

#ifndef PORT
    #define PORT 57748
#endif

#define LISTEN_SIZE 5
#define WELCOME_MSG "Welcome to \n  ___  ___   ___  ___   ___   ___    ____  _    _  ____  ____  ____  ____  ____\n / __)/ __) / __)(__ \\ / _ \\ / _ \\  (_  _)( \\/\\/ )(_  _)(_  _)(_  _)( ___)(  _ \\\n( (__ \\__ \\( (__  / _/( (_) )\\_  /    )(   )    (  _)(_   )(    )(   )__)  )   /\n \\___)(___/ \\___)(____)\\___/  (_/    (__) (__/\\__)(____) (__)  (__) (____)(_)\\_)\n\nEnter your username: \r\n"
#define SEND_MSG "send "
#define SHOW_MSG "show "
#define FOLLOW_MSG "follow "
#define UNFOLLOW_MSG "unfollow "
#define BUF_SIZE 256
#define MSG_LIMIT 8
#define FOLLOW_LIMIT 5
#define SERVER_SHUTDOWN_MSG "\nThank you for using the Twerver!\nShutting down server...clients will still have to disconnect on their end.\n"

struct client {
    int fd;
    struct in_addr ipaddr;
    char username[BUF_SIZE];
    char message[MSG_LIMIT][BUF_SIZE];
    struct client *following[FOLLOW_LIMIT]; // Clients this user is following
    struct client *followers[FOLLOW_LIMIT]; // Clients who follow this user
    char inbuf[BUF_SIZE]; // Used to hold input from the client
    char *in_ptr; // A pointer into inbuf to help with partial reads
    struct client *next;
};


// Provided functions. 
void add_client(struct client **clients, int fd, struct in_addr addr);
void remove_client(struct client **clients, int fd);

// These are some of the function prototypes that we used in our solution 
// You are not required to write functions that match these prototypes, but
// you may find them helpful when thinking about operations in your program.

// Send the message in s to all clients in active_clients. 
void announce(struct client **active_clients, char *s);

// Move client c from new_clients list to active_clients list. 
void activate_client(struct client *c, 
    struct client **active_clients_ptr, struct client **new_clients_ptr);


// The set of socket descriptors for select to monitor.
// This is a global variable because we need to remove socket descriptors
// from allset when a write to a socket fails. 
fd_set allset;


void activate_client(struct client *c, 
    struct client **active_clients_ptr, struct client **new_clients_ptr) {

    struct client **p;
    struct client **prev = NULL;

    for (p = new_clients_ptr; (*p)->fd != c->fd || ((*p)->next) != NULL; p = &(*p)->next) {
        prev = p;
    }

    // We are assuming that c is in new_clients, so when the loop ends
    // prev is the node before c

    //if only one client in new clients and no active clients
    //so if the loop doesn't execute at all because the next node of c is NULL
    // AND active clients is empty
    if (prev == NULL && c->next == NULL && *active_clients_ptr == NULL) {
        *new_clients_ptr = NULL;
        *active_clients_ptr = c;
    }
    //if only one client in new clients and at least one active client
    else if (prev == NULL && c->next == NULL && *active_clients_ptr != NULL) {
        *new_clients_ptr = NULL;
        c->next = *active_clients_ptr;
        *active_clients_ptr = c;
    }
    //if more than one client in new clients and no active clients
    else if (*active_clients_ptr == NULL) {
        //if c is the head of new clients
        if (prev == NULL && c->next != NULL) {
            *new_clients_ptr = c->next;
            c->next = NULL;
            *active_clients_ptr = c;
        }
        //if c is not the head of new clients
        else {
            (*prev)->next = c->next;
            c->next = *active_clients_ptr; //which should be null
            *active_clients_ptr = c;
        }
    }
    //if at least one client in new clients and at least one active client
    else if (*active_clients_ptr != NULL) {
        //if c is the head of new clients
        if (prev == NULL && c->next != NULL) {
            *new_clients_ptr = c->next;
            c->next = *active_clients_ptr;
            *active_clients_ptr = c;
        }
        //if c is not the head of new clients
        else {
            (*prev)->next = c->next;
            c->next = *active_clients_ptr;
            *active_clients_ptr = c;
        }
    }

}

/* 
 * Create a new client, initialize it, and add it to the head of the linked
 * list.
 */
void add_client(struct client **clients, int fd, struct in_addr addr) {
    struct client *p = malloc(sizeof(struct client));
    if (!p) {
        perror("malloc");
        exit(1);
    }

    printf("Adding client %s\n", inet_ntoa(addr));
    p->fd = fd;
    p->ipaddr = addr;
    p->username[0] = '\0';
    p->in_ptr = p->inbuf;
    p->inbuf[0] = '\0';
    p->next = *clients;

    // initialize messages to empty strings
    for (int i = 0; i < MSG_LIMIT; i++) {
        p->message[i][0] = '\0';
    }

    // initialize followers and following to NULL
    for (int i = 0; i < FOLLOW_LIMIT; i++) {
        p->followers[i] = NULL;
        p->following[i] = NULL;
    }

    *clients = p;
}

/* 
 * Remove client from the linked list and close its socket.
 * Also, remove socket descriptor from allset.
 */
void remove_client(struct client **clients, int fd) {
    struct client **p;

    for (p = clients; *p && (*p)->fd != fd; p = &(*p)->next)
        ;

    // Now, p points to (1) top, or (2) a pointer to another client
    // This avoids a special case for removing the head of the list
    if (*p) {
        // TODO: Remove the client from other clients' following/followers
        // lists

        // Remove the client
        struct client *t = (*p)->next;
        printf("Removing client %d %s\n", fd, inet_ntoa((*p)->ipaddr));
        FD_CLR((*p)->fd, &allset);
        close((*p)->fd);
        free(*p);
        *p = t;
    } else {
        fprintf(stderr, 
            "Trying to remove fd %d, but I don't know about it\n", fd);
    }
}

/*
 * Returns 1 if the given username is available to use and is not the 
 * empty string. Returns 0 if otherwise
 */
int check_username(char *username, struct client **clients) {
    if (strlen(username) == 0) {
        return 0;
    }

    struct client **p;

    for (p = clients; *p != NULL; p = &(*p)->next) {

        if (strcmp((*p)->username, username) == 0) {
            return 0;
        }
    }

    return 1;
}

/*
 * Searches for a client with the given username in the given client list,
 * returning the client belonging to that username if found and NULL otherwise
 */
struct client *find_user(char *username, struct client **clients) {
    struct client **p;
    for (p = clients; *p != NULL; p = &(*p)->next) {
        if (strcmp((*p)->username, username) == 0) {
            return *p;
        }
    }

    return NULL;
}

/*
 * Returns 1 if the user has hit the msg limit, 0 otherwise
 */
int check_for_msg_limit(struct client *user) {
    for (int i = 0; i < MSG_LIMIT; i++) {
        if ((user->message)[i][0] == '\0') {
            return 0;
        }
    }

    return 1;
}

/*
 * Add user to the user to follow's follower list and
 * add user to follow to the user's following list and 
 * returns 1 if successful, 0 otherwise
 */
int follow(struct client *user, struct client *user_to_follow) {

    int saved_follower_index = -1;

    //Add user to the user to follow's follower list
    for (int i = 0; i < FOLLOW_LIMIT; i++) {
        if ((user_to_follow->followers)[i] == NULL) {
            saved_follower_index = i;
            break;
        }
    }

    if (saved_follower_index != -1) { 
        //Add user to follow to the user's following list
        for (int i = 0; i < FOLLOW_LIMIT; i++) {
            if ((user->following)[i] == NULL) {
                (user->following)[i] = user_to_follow;
                (user_to_follow->followers)[saved_follower_index] = user;
                return 1;
            }
        } 
    }

    return 0;
}

/*
 * Remove user from the user to unfollow's follower list and
 * remove user to unfollow from the user's following list and 
 * returns 1 if successful, 0 otherwise
 */
int unfollow(struct client *user, struct client *user_to_unfollow) {

    int saved_follower_index = -1;

    //Remove user from the user to follow's follower list
    for (int i = 0; i < FOLLOW_LIMIT; i++) {
        if ((user_to_unfollow->followers)[i] == user) {
            saved_follower_index = i;
            break;
        }
    }

    if (saved_follower_index != -1) { 
        //Remove user to unfollow from the user's following list
        for (int i = 0; i < FOLLOW_LIMIT; i++) {
            if ((user->following)[i] == user_to_unfollow) {
                (user->following)[i] = NULL;
                (user_to_unfollow->followers)[saved_follower_index] = NULL;
                return 1;
            }
        } 
    }

    return 0;
}

/*
 * Remove user from follower's following list,
 * remove user from following's follower list, and
 * remove user from list of active clients
 */
void quit(struct client *user, struct client **active_clients) {
    
    for (int i = 0; i < FOLLOW_LIMIT; i++) {
        //for each follower, remove client from their following list
        if ((user->followers)[i] != NULL) {
            unfollow((user->followers)[i], user);
        }
        //for each following, remove client from their follower list
        if ((user->following)[i] != NULL) {
            unfollow(user, (user->following)[i]);
        }
    }

    printf("Lost connection to %s, client %d has now been disconnected.\n", 
                        user->username, user->fd); 

    remove_client(active_clients, user->fd);
}

/*
 * Parses any outgoing text to be correctly read by clients
 * and send that. Returns 1 if successful, 0 if not
 */
int Write(int fd, char *message) {
    char formatted_message[strlen(message) + 3];
    strncpy(formatted_message, message, strlen(message));
    *(formatted_message + strlen(message)) = '\r';
    *(formatted_message + strlen(message) + 1) = '\n';
    *(formatted_message + strlen(message) + 2) = '\0';

    if (write(fd, formatted_message, strlen(formatted_message)) < strlen(formatted_message)) {
        return 0;
    }
    else {
        return 1;
    }
}

void announce(struct client **active_clients, char *s) {
    struct client **p;

    for (p = active_clients; *p != NULL; p = &(*p)->next) {
        if (!Write((*p)->fd, s)) {
            quit(*p, active_clients);
        }
    }
}

/*
 * Write all messages from the user's following list to the client
 */
void show (struct client *user, struct client **active_clients) {
    int i = 0;
    struct client **p;

    for (p = user->following; *p != NULL; p = &(user->following[i])) {
        for (int j = 0; j < MSG_LIMIT; j++) {
            if ((*p)->message[j][0] != '\0') {
                char message[strlen((*p)->username) + strlen((*p)->message[j]) + 1];
                sprintf(message, "%s: %s", (*p)->username, (*p)->message[j]);

                if (!Write(user->fd, message)) {
                    quit(user, active_clients);                      
                }
            }
        }
        i++; // proceed to next user's messages
    }
}

/*
 * Add a message to user's message list and announce message to all 
 * of user's followers
 */
void tweet (struct client *user, char *message) {
    //add message to user's messages
    for (int j = 0; j < MSG_LIMIT; j++) {
        if (user->message[j][0] == '\0') {
            strcpy(user->message[j], message);
            break;
        }
    }

    char formatted_tweet[strlen(user->username) + strlen(message) + 2];
    sprintf(formatted_tweet, "%s: %s", user->username, message);

    //announce message to user's followers
    announce(user->followers, formatted_tweet);
}

/*
 * Properly read and format input from user and save it to user's buffer
 */
int Read (struct client *user, struct client **clients) {

    char temp_buf[BUF_SIZE] = {'\0'};
    int has_network_newline = 0;
    char *newline_addr = NULL;
    int buf_occupied_space = 0;
    int nbytes = 0;


    while (!has_network_newline) {

        if ((nbytes = read(user->fd, temp_buf + buf_occupied_space, BUF_SIZE - buf_occupied_space)) > 0) {
            buf_occupied_space += nbytes;
            *(temp_buf + buf_occupied_space) = '\0';

            if ((newline_addr = strstr(temp_buf, "\r\n")) == NULL && buf_occupied_space < BUF_SIZE) {
                //do nothing
            }
            else { //if complete message
                has_network_newline = 1; //break
                *newline_addr = '\0';
            }
        }
        else {
            quit(user, clients);
            printf("Cannot read from client %d, now disconnecting client.\n", user->fd);
            return 1;
        }
    }

    //format
    printf("Read input from client %d, \"%s\"\n", user->fd, temp_buf);
    strncpy(user->inbuf, temp_buf, BUF_SIZE);
    return 0;
    
}

void close_server_handler(int code) {
    printf("\033[0m");
    printf(SERVER_SHUTDOWN_MSG);

    exit(0);
}


int main (int argc, char **argv) {
    printf("\033[1;36m"); //set colour in terminal to blue to help distinguish server from clients

    int clientfd, maxfd, nready;
    struct client *p;
    struct sockaddr_in q;
    fd_set rset;

    // If the server writes to a socket that has been closed, the SIGPIPE
    // signal is sent and the process is terminated. To prevent the server
    // from terminating, ignore the SIGPIPE signal. 
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    struct sigaction closing_server;
    closing_server.sa_handler = close_server_handler;
    closing_server.sa_flags = 0;
    sigemptyset(&closing_server.sa_mask);
    sigaddset(&closing_server.sa_mask, SIGINT);

    if (sigaction(SIGINT, &closing_server, NULL) == -1){
      perror("sigaction");
      exit(1);
    }


    // A list of active clients (who have already entered their names). 
    struct client *active_clients = NULL;

    // A list of clients who have not yet entered their names. This list is
    // kept separate from the list of active clients, because until a client
    // has entered their name, they should not issue commands or 
    // or receive announcements. 
    struct client *new_clients = NULL;

    struct sockaddr_in *server = init_server_addr(PORT);
    int listenfd = set_up_server_socket(server, LISTEN_SIZE);
    free(server);

    // Initialize allset and add listenfd to the set of file descriptors
    // passed into select 
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    // maxfd identifies how far into the set to search
    maxfd = listenfd;

    while (1) {
        // make a copy of the set before we pass it into select
        rset = allset;

        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready == -1) {
            perror("select");
            exit(1);
        } else if (nready == 0) {
            continue;
        }

        // check if a new client is connecting
        if (FD_ISSET(listenfd, &rset)) {
            printf("A new client is connecting\n");
            clientfd = accept_connection(listenfd, &q);

            FD_SET(clientfd, &allset);
            if (clientfd > maxfd) {
                maxfd = clientfd;
            }
            printf("Connection from %s\n", inet_ntoa(q.sin_addr));
            add_client(&new_clients, clientfd, q.sin_addr);
            char *greeting = WELCOME_MSG;
            if (write(clientfd, greeting, strlen(greeting)) == -1) {
                fprintf(stderr, 
                    "Write to client %s failed\n", inet_ntoa(q.sin_addr));
                remove_client(&new_clients, clientfd);
            }
        }

        // Check which other socket descriptors have something ready to read.
        // The reason we iterate over the rset descriptors at the top level and
        // search through the two lists of clients each time is that it is
        // possible that a client will be removed in the middle of one of the
        // operations. This is also why we call break after handling the input.
        // If a client has been removed, the loop variables may no longer be 
        // valid.
        int cur_fd, handled;
        for (cur_fd = 0; cur_fd <= maxfd; cur_fd++) {
            if (FD_ISSET(cur_fd, &rset)) {
                handled = 0;

                // Check if any new clients are entering their names
                for (p = new_clients; p != NULL; p = p->next) {
                    if (cur_fd == p->fd) {
                        // handle input from a new client who has not yet
                        // entered an acceptable name

                        if (Read(p, &new_clients) != 1) { // read something
                        
                            printf("Got username from client %d\n", cur_fd);

                        }

                        if (check_username(p->inbuf, &active_clients)) {
                            printf("Verified username from client %d, now activating\n", cur_fd);
                            strcpy(p->username, p->inbuf);

                            activate_client(p, &active_clients, &new_clients);

                            char message[strlen(p->username) + strlen(" has joined Twitter.") + 1];
                            sprintf(message, "%s has joined Twitter.", p->username);
                            announce(&active_clients, message);
                            printf("%s\n", message);
                            printf("Announced above message to everyone on Twitter.\n");
                        }
                        else {
                            char message[] = "This username is not available, please enter another one.";
                            if (!Write(cur_fd, message)) {
                                remove_client(&new_clients, cur_fd);
                                printf("Lost connection to client %d, now disconnecting.\n", cur_fd);
                            }
                        }
                            
                        
                       
                        handled = 1;
                        break;
                    }
                }

                if (!handled) {
                    // Check if this socket descriptor is an active client
                    for (p = active_clients; p != NULL; p = p->next) {
                        if (cur_fd == p->fd) {
                            // handle input from an active client
                            Read(p, &active_clients); // read something

                            printf("Got input from client %d, (user %s)\n", cur_fd, p->username);

                            //if follow <user>
                            if (strncmp(p->inbuf, FOLLOW_MSG, strlen(FOLLOW_MSG)) == 0) {

                                char *username = p->inbuf + strlen(FOLLOW_MSG);

                                //if username is occupied by a user
                                if (!check_username(username, &active_clients)) {
                                    //FOLLOW the user 
                                    if (follow(p, find_user(username, &active_clients))) {
                                        printf("%s has followed %s\n", p->username, username);

                                        char message[strlen("You are now following ") + strlen(username) + 4];
                                        sprintf(message, "You are now following %s.", username);

                                        if (!Write(cur_fd, message)) {
                                            quit(p, &active_clients); 
                                        }
                                    }
                                    else {
                                        printf("Either %s's follower limit or %s's following limit has been exceeded.\n", 
                                            username, p->username);

                                        char message[strlen("Cannot follow ") + strlen(username) + 4];
                                        sprintf(message, "Cannot follow %s.", username);

                                        if (!Write(cur_fd, message)) {
                                            quit(p, &active_clients); 
                                        }
                                    }
                                }
                                //otherwise
                                else {
                                    printf("User %s has tried to follow a non-existent user\n", p->username);
                                    //write to client, user does not exist
                                    char message[] = "User does not exist.";

                                    if (!Write(cur_fd, message)) {
                                            quit(p, &active_clients); 
                                    }
                                }
                            }
                            //if unfollow <user>
                            else if (strncmp(p->inbuf, UNFOLLOW_MSG, strlen(UNFOLLOW_MSG)) == 0) {
                                char *username = p->inbuf + strlen(UNFOLLOW_MSG);

                                //if username is occupied by a user
                                if (!check_username(username, &active_clients)) {
                                    //UNFOLLOW the user (
                                        //remove client from user's following list, 
                                        //remove user from client's follower list)
                                    if (unfollow(p, find_user(username, &active_clients))) {
                                        printf("%s has unfollowed %s\n", p->username, username);

                                        char message[strlen("You are no longer following ") + strlen(username) + 4];
                                        sprintf(message, "You are no longer following %s.", username);

                                        if (!Write(cur_fd, message)) {
                                            quit(p, &active_clients); 
                                        } 
                                    }
                                    else {
                                        printf("%s already was not following %s\n.", 
                                            p->username, username);

                                        char message[strlen("Cannot unfollow ") + strlen(username) + 4];
                                        sprintf(message, "Cannot unfollow %s.", username);

                                        if (!Write(cur_fd, message)) {
                                            quit(p, &active_clients); 
                                        }
                                    }
                                }
                                //otherwise
                                else {
                                    printf("User %s has tried to follow a non-existent user\n", p->username);
                                    //write to client, user does not exist
                                    char message[] = "User does not exist.";

                                    if (!Write(cur_fd, message)) {
                                            quit(p, &active_clients); 
                                    }
                                }
                            }
                            //if show
                            else if (strncmp(p->inbuf, SHOW_MSG, 4) == 0) {
                                //SHOW all messages from following list
                                show(p, &active_clients);
                                printf("Just displayed all of feed to user %s\n", p->username);
                            }

                            //if send <msg>
                            else if (strncmp(p->inbuf, SEND_MSG, strlen(SEND_MSG)) == 0) {
                                char *tweet_msg = p->inbuf + strlen(SEND_MSG);

                                //if user has hit the MSG_LIMIT
                                if (check_for_msg_limit(p)) {
                                    printf("Failed attempt from %s to send a tweet, has hit msg limit\n", 
                                        p->username);
                                    //write to client that they cannot send the message
                                    char message[] = "You have hit the message limit.";

                                    if (!Write(cur_fd, message)) {
                                        quit(p, &active_clients); 
                                    }
                                }
                                //otherwise
                                else {
                                    //tweet the message to client's followers
                                    tweet(p, tweet_msg);
                                    printf("%s has tweeted something\n", p->username);
                                }
                            }
                            //if quit
                            else if (strncmp(p->inbuf, "quit", 4) == 0) {
                                quit(p, &active_clients);
                            }
                            else if (strncmp(p->inbuf, "^C", 2) != 0) {
                                //write to user: "Invalid command"   
                                char message[] = "Invalid command";

                                if (!Write(cur_fd, message)) {
                                    quit(p, &active_clients); 
                                } 

                                printf("User %s has issued an invalid command\n", p->username);
                            }


                            break;
                        }
                    }
                }
            }
        }
    }
    
    return 0;
}
