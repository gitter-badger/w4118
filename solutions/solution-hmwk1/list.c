#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "list.h"

void free_node(struct node *n)
{
	if (n->string_data)
		free(n->string_data);
	free(n);
}

void free_all_nodes(struct node **head)
{
	struct node *cur_node = NULL;
	struct node *prev = NULL;

	if (head == NULL)
		return;

	cur_node = *head;
	while (cur_node) {
		prev = cur_node;
		cur_node = cur_node->next;
		free_node(prev);
	}
}

int append_node_dupe(struct node **head, char *data, int append_dupe)
{
	struct node *cur_node = NULL;
	struct node *prev = NULL;
	struct node *new_node;

	if (head != NULL)
		cur_node = *head;

	/* Find end of the list */
	while (cur_node) {
		/* Do not append if no-dupes requested */
		if (!append_dupe && strcmp(cur_node->string_data, data) == 0)
			return 0;
		prev = cur_node;
		cur_node = cur_node->next;
	}

	/* Create a new node */
	new_node = malloc(sizeof(struct node));
	if (new_node == NULL)
		return -1;
	new_node->string_data = malloc(sizeof(char)*strlen(data)+1);
	if (new_node->string_data == NULL) {
		free(new_node);
		return -1;
	}
	strcpy(new_node->string_data, data);
	new_node->next = NULL;

	if (prev)
		prev->next = new_node;
	else
		*head = new_node;

	return 0;
}

int append_node(struct node **head, char *data)
{
	return append_node_dupe(head, data, 0);
}

int remove_node_by_val(struct node **head, char *data)
{
	int found = 0;
	struct node *cur_node = NULL;
	struct node *prev = NULL;

	if (head == NULL)
		return 0;
	cur_node = *head;

	while (cur_node) {
		if (cur_node->string_data) {
			if (!strcmp(cur_node->string_data, data)) {
				found = 1;
				break;
			}
		}
		prev = cur_node;
		cur_node = cur_node->next;
	}

	if (found) {
		if (prev)
			prev->next = cur_node->next;
		if (cur_node == *head)
			*head = cur_node->next;
		free_node(cur_node);
	}

	return 0;
}

struct node *pop_front(struct node **head)
{
	struct node *ret_node = NULL;

	if (head == NULL)
		return NULL;

	ret_node = *head;
	*head = ret_node->next;

	return ret_node;
}

struct node *get_node(struct node **head, int n)
{
	int i;
	struct node *cur_node = NULL;

	if (head == NULL)
		return NULL;

	cur_node = *head;

	for (i = 0; i < n; ++i)
		cur_node = cur_node->next;

	return cur_node;
}
