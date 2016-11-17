#ifndef _SIMPLE_SHELL_H_
#define _SIMPLE_SHELL_H_

/* A built-in command and its corresponding function */
struct command {
	const char *name;
	int (*handle_cmd)(char **argv);
};

void process_line(char *line, char add_to_history);

#endif
