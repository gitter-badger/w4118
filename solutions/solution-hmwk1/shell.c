#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "shell.h"
#include "list.h"

/* List head for path and history lists */
static struct node *PATH_HEAD;
static struct node *HISTORY_HEAD;
static int HISTORY_SZ;
static const int MAX_HISTORY_SZ = 100;
static char *DELIMS = " \t";

/* Pointer to the buffer which contains input string */
char *input_line;

void release_all_resources(void)
{
	free(input_line);
	free_all_nodes(&PATH_HEAD);
	free_all_nodes(&HISTORY_HEAD);
}

static int handle_cd_cmd(char **argv)
{
	if (chdir(argv[1]) < 0) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int handle_exit_cmd(char **argv)
{
	release_all_resources();
	exit(0);
	return -1; /* Unreachable */
}

static void print_history(void)
{
	struct node *history = HISTORY_HEAD;
int i = 0;

	while (history) {
		printf("%d %s\n", i++, history->string_data);
		history = history->next;
	}
}

static void clear_history(struct node **head, int *history_sz)
{
	while (*head) {
		struct node *popped_node = pop_front(head);

		free_node(popped_node);
		--(*history_sz);
	}
}

static int is_int(char *to_check)
{
	int i = 0;
	int l = strlen(to_check);

	while (i < l) {
		char c = *(to_check + (i++));

		if (!isdigit(c))
			return 0;
	}

	return 1;
}

static int handle_history_cmd(char **argv)
{
	if (argv[1] == NULL) {
		print_history();
		return 0;
	} else if (!strcmp(argv[1], "-c")) {
		clear_history(&HISTORY_HEAD, &HISTORY_SZ);

		return 0;
	} else if (is_int(argv[1])) {
		int hist_i = atoi(argv[1]);
		struct node *node_by_idx;
		char *line_dup;

		if (hist_i < 0 || hist_i > HISTORY_SZ - 1) {
			fprintf(stderr, "error: offset invalid: %d\n", hist_i);
			return -1;
		}

		node_by_idx = get_node(&HISTORY_HEAD, hist_i);

		if (node_by_idx == NULL) {
			fprintf(stderr, "error: no cmd at offset\n");
			return -1;
		}

		/* Need to dupe b/c process_line uses strtok */
		line_dup = strdup(node_by_idx->string_data);
		process_line(line_dup, 0);

		free(line_dup);
		return 0;
	}

	fprintf(stderr, "error: invalid arguments\n");
	return -1;
}

static const struct command commands[] = {
	{ "cd", handle_cd_cmd },
	{ "exit", handle_exit_cmd },
	{ "history", handle_history_cmd },
	{ NULL, NULL }
};

const struct command *check_builtin_cmd(char *input)
{
	const struct command *cmd = NULL;

	for (cmd = commands; cmd->name != NULL; ++cmd) {
		if (strcmp(input, cmd->name))
			continue;
		/* Matched a built-in command */
		return cmd;
	}
	return NULL;
}

/* Check syntax */
static int preprocess_line(char *line, const struct command **cmd_)
{
	char *line_dup, *line_dup_org;
	char *token;
	const struct command *cmd;

	line_dup = strdup(line);
	line_dup_org = line_dup; /* For free(), keep original pointer */
	if (line_dup == NULL) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		return -1;
	}

	token = strtok(line_dup, " \t");
	if (token == NULL)
		return 0;

	cmd = check_builtin_cmd(token);
	if (cmd != NULL)
		*cmd_ = cmd;

	free(line_dup_org);
	return 0;
}

/*
 * Tokenizes the string based on the delims. Stores pointers to each token
 * in the array argv. Returns the number of tokens.
 */
int tokenize(char *str, char **argv, char *delims, int max_tokens)
{
	int argc = 0;

	for (argv[argc] = strtok(str, delims);
			argv[argc] != NULL;
			argv[argc] = strtok(NULL, delims)) {
		if (++argc >= max_tokens) {
			fprintf(stderr, "error: too many tokens\n");
			return -1;
		}
	}
	return argc;
}

/* Attempts to kick off the command specified by line as a child process. The
 * child process will accept input from the i/o resource specified by
 * read_end_fd and write output to the i/o resource specified by write_end_fd.
 * If read_end_fd == -1, the child process will read from stdin. If
 * write_end_fd == -1, the child process will write to stdout.
 */
int handle_executable(char *line, int read_end_fd, int write_end_fd)
{
	char *argv[_POSIX_ARG_MAX];
	pid_t pid;

	/* Command was invalid, i.e. too many args */
	if (tokenize(line, argv, DELIMS, _POSIX_ARG_MAX) < 0)
		return -1;

	pid = fork();
	if (pid == -1)
		goto error;


	if (pid == 0) {
		if ((read_end_fd != -1)
				&& (dup2(read_end_fd, STDIN_FILENO) < 0))
			goto error;

		if ((write_end_fd != -1)
				&& (dup2(write_end_fd, STDOUT_FILENO) < 0))
			goto error;

		execv(argv[0], argv);

		/* Should not be reached. */
		fprintf(stderr, "error: %s\n", strerror(errno));
		exit(1);
	}

	return 0;

error:
	fprintf(stderr, "error: %s\n", strerror(errno));
	return -1;
}

void add_history(char *line)
{
	/*
	 * We want to first remove the oldest entry if the history
	 * list is at maximum size, then add the new entry.
	 */
	if (HISTORY_SZ >= MAX_HISTORY_SZ) {
		struct node *oldest_history = pop_front(&HISTORY_HEAD);

		if (oldest_history != NULL) {
			free_node(oldest_history);
			--HISTORY_SZ;
		}
	}

	append_node_dupe(&HISTORY_HEAD, line, 1);
	++HISTORY_SZ;
}

/* Consecutive | symbols result in an invalid pipeline */
int is_valid_pipeline(char *pipeline)
{
	char *curptr;

	/* Empty string is valid */
	if (*pipeline == '\0')
		return 1;

	/* Start curptr at second character */
	for (curptr = pipeline + 1; *curptr != '\0'; curptr++) {
		if (*curptr == '|' && *(curptr - 1) == '|')
			return 0;
	}

	/* If the first or last character is a |, it's an invalid pipeline */
	if ((*(curptr - 1) == '|') | (*pipeline == '|'))
		return 0;

	return 1;
}

/*
 * Tokenizes the line into a series of commands that form a pipeline. Runs the
 * commands in the pipeline, chaining them together with pipes.
 */
void process_line(char *line, char add_to_history)
{
	const struct command *cmd = NULL;
	char *argv[_POSIX_ARG_MAX],
	     *piped_commands[_POSIX_CHILD_MAX],
	     *cur_cmd,
	     *line_dup;
	int cur_cmd_idx = 0,
	    num_piped_commands,
	    exit_status = 0,
	    pipes[2],
	    read_fd = -1,
	    write_fd = -1;

	/* line must be duplicated because original line is strtok'd. */
	line_dup = strdup(line);
	if (line_dup == NULL) {
		fprintf(stderr, "error: %s\n", strerror(errno));
		goto cleanup;
	}

	if (!is_valid_pipeline(line)) {
		fprintf(stderr, "error: invalid pipeline\n");
		goto cleanup;
	}

	/* Break the line into commands that are separated by |. */
	num_piped_commands =
		tokenize(line, piped_commands, "|", _POSIX_CHILD_MAX);

	/*
	 * This loop executes each command in the pipeline, linking it to the
	 * next command with a pipe.
	 */
	for (cur_cmd = piped_commands[cur_cmd_idx];
			cur_cmd != NULL;
			cur_cmd = piped_commands[++cur_cmd_idx]) {

		if (cur_cmd_idx == 0) {
			/*
			 * If this is the first command in the pipeline, let it
			 * read from stdin.
			 */
			read_fd = -1;
		} else {
			/*
			 * Otherwise, this command's stdin must be the
			 * stdout of the last command.
			 */
			read_fd = pipes[0];
		}

		if (piped_commands[cur_cmd_idx + 1] == NULL) {
			/* Let the last command write to stdout. */
			write_fd = -1;
		} else {
			/*
			 * If this is not the last command, stdout must be
			 * collected in a new pipe, to be read by the next
			 * command in the pipeline.
			 */
			if (pipe(pipes) < 0) {
				fprintf(stderr, "error: %s", strerror(errno));
				goto cleanup;
			}
			write_fd = pipes[1];
		}

		/* Checks for built-in command */
		if (preprocess_line(cur_cmd, &cmd) < 0)
			goto cleanup;

		/*
		 * Only attempt to execute a builtin command if there's no
		 * pipeline.
		 */
		if (cmd != NULL && num_piped_commands == 1) {
			tokenize(cur_cmd, argv, DELIMS, _POSIX_ARG_MAX);

			/* exit will exit, so free memory first. */
			if (!strcmp(cmd->name, "exit"))
				free(line_dup);

			/* never add history to history */
			if (!strcmp(cmd->name, "history"))
				add_to_history = 0;

			/*
			 * Use function pointer to execute the handler
			 * implementation for each built-in command.
			 *
			 * You will see a similar pattern often in the
			 * Linux kernel. =]
			 */
			cmd->handle_cmd(argv);
			cmd = NULL;
		} else if (handle_executable(cur_cmd, read_fd, write_fd) < 0) {
			goto cleanup;
		}

		/*
		 * The shell process itself does not need access to the pipe,
		 * so we close it. This is necessary - when the write end of a
		 * pipe is completely closed, the read end receives an EOF. If
		 * the write end remains open in some process, all reading
		 * processes will continue to hang, believing that more input
		 * may become available on stdin.
		 */
		if (read_fd != -1) {
			close(read_fd);
			read_fd = -1;
		}

		if (write_fd != -1) {
			close(write_fd);
			write_fd = -1;
		}
	}

cleanup:
	if (add_to_history)
		add_history(line_dup);

	if (read_fd != -1)
		close(read_fd);

	if (write_fd != -1)
		close(write_fd);

	/* Wait for all of the children to exit. */
	for (;;) {
		if (wait(&exit_status) == -1) {
			/*
			 * ECHILD indicates that there are no children left to
			 * wait for. Any other value of errno is an error.
			 */
			if (errno == ECHILD)
				break;
			fprintf(stderr, "error: %s\n", strerror(errno));
		}
	}

	free(line_dup);
}

static inline void print_prompt(void)
{
	fprintf(stderr, "$");
	fflush(stderr);
}

int main(int argc, char **argv)
{
	ssize_t n = 0;
	size_t len = 0;

	print_prompt();

	while ((n = getline(&input_line, &len, stdin)) > 0) {
		if (n > 1) {
			/* Remove newline character */
			input_line[n-1] = '\0';
			process_line(input_line, 1);
		}
		print_prompt();
	}

	if (n < 0 && !feof(stdin))
		fprintf(stderr, "error: %s\n", strerror(errno));

	release_all_resources();

	return 0;
}
