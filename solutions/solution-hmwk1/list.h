#ifndef _LIST_H_
#define _LIST_H_

struct node {
	struct node *next;
	char *string_data;
};

void free_node(struct node *n);
void free_all_nodes(struct node **head);
int append_node(struct node **head, char *data);
int append_node_dupe(struct node **head, char *data, int append_dupe);
int remove_node_by_val(struct node **head, char *data);
struct node *pop_front(struct node **head);
struct node *get_node(struct node **head, int n);

#endif
