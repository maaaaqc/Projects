/**
 *  @project    :   Container
 *  @auther     :   Qingchuan Ma
 *  @instructor :   Shabir Abdul Samadh (some of the code were contructed by the instructor)
*/

#include "sr_container.h"

struct cgroup_setting self_to_task = {
	.name = "tasks",
	.value = "0"
};

struct cgroups_control *cgroups[6] = {
	& (struct cgroups_control) {
		.control = CGRP_BLKIO_CONTROL,
		.settings = (struct cgroup_setting *[]) {
			& (struct cgroup_setting) {
				.name = "blkio.weight",
				.value = "64"
			},
			&self_to_task,             // must be added to all the new controls added
			NULL                       // NULL at the end of the array
		}
	},
	NULL                               // NULL at the end of the array
};

int main(int argc, char **argv)
{
    struct child_config config = {0};
    int option = 0;
    int sockets[2] = {0};
    pid_t child_pid = 0;
    int last_optind = 0;
    bool found_cflag = false;
    int num_set = 0;
    bool initialized = false;
    struct cgroups_control *cpu = NULL;
    struct cgroups_control *cpuset = NULL;
    struct cgroups_control *pids = NULL;
    struct cgroups_control *memory = NULL;
    struct cgroups_control *blkio = NULL;

    while ((option = getopt(argc, argv, "c:m:u:C:s:p:M:r:w:H:")))
    {
        if (found_cflag)
            break;

        switch (option)
        {
        case 'c':
            config.argc = argc - last_optind - 1;
            config.argv = &argv[argc - config.argc];
            found_cflag = true;
            break;
        case 'm':
            config.mount_dir = optarg;
            break;
        case 'u':
            if (sscanf(optarg, "%d", &config.uid) != 1)
            {
                fprintf(stderr, "UID not as expected: %s\n", optarg);
                cleanup_stuff(argv, sockets);
                return EXIT_FAILURE;
            }
            break;
        case 'C':
            num_set = 3;
            cpu = (struct cgroups_control *) calloc(1, sizeof(struct cgroups_control));
            strcpy(cpu->control, CGRP_CPU_CONTROL);
            cpu->settings = (struct cgroup_setting **) calloc(1, num_set*sizeof(struct cgroup_setting*));
            for (int i = 0; i < num_set; i++){
                cpu->settings[i] = (struct cgroup_setting *) calloc(1, sizeof(struct cgroup_setting));
            }
            strcpy(cpu->settings[0]->name, "cpu.shares");
            strcpy(cpu->settings[0]->value, optarg);
            memcpy(cpu->settings[1], &self_to_task, sizeof(struct cgroup_setting));
            cpu->settings[2] = NULL;
            for (int j = 0; j < 5; j++){
                if (cgroups[j] == NULL){
                   cgroups[j] = cpu;
                   cgroups[j+1] = NULL;
                   break;
                }
            }
            break;
        case 's':
            num_set = 4;
            cpuset = (struct cgroups_control *) calloc(1, sizeof(struct cgroups_control));
            strcpy(cpus->control, CGRP_CPU_SET_CONTROL);
            cpuset->settings = (struct cgroup_setting **) calloc(1, num_set*sizeof(struct cgroup_setting*));
            for (int i = 0; i < num_set; i++){
                cpuset->settings[i] = (struct cgroup_setting *) calloc(1, sizeof(struct cgroup_setting));
            }
            strcpy(cpuset->settings[0]->name, "cpuset.cpus");
            strcpy(cpuset->settings[0]->value, optarg);
            strcpy(cpuset->settings[1]->name, "cpuset.mems");
            strcpy(cpuset->settings[1]->value, "0");
            memcpy(cpuset->settings[2], &self_to_task, sizeof(struct cgroup_setting));
            cpuset->settings[3] = NULL;
            for (int j = 0; j < 5; j++){
                if (cgroups[j] == NULL){
                    cgroups[j] = cpuset;
                    cgroups[j+1] = NULL;
                    break;
                }
            }
            break;
        case 'p':
            num_set = 3;
            pids = (struct cgroups_control *) calloc(1, sizeof(struct cgroups_control));
            strcpy(pids->control, CGRP_PIDS_CONTROL);
            pids->settings = (struct cgroup_setting **) calloc(1, num_set*sizeof(struct cgroup_setting*));
            for (int i = 0; i < num_set; i++){
                pids->settings[i] = (struct cgroup_setting *) calloc(1, sizeof(struct cgroup_setting));
            }
            strcpy(pids->settings[0]->name, "pids.max");
            strcpy(pids->settings[0]->value, optarg);
            memcpy(pids->settings[1], &self_to_task, sizeof(struct cgroup_setting));
            pids->settings[2] = NULL;
            for (int j = 0; j < 5; j++){
                if (cgroups[j] == NULL){
                    cgroups[j] = pids;
                    cgroups[j+1] = NULL;
                    break;
                }
            }
            break;
        case 'M':
            num_set = 3;
            memory = (struct cgroups_control *) calloc(1, sizeof(struct cgroups_control));
            strcpy(memory->control, CGRP_MEMORY_CONTROL);
            memory->settings = (struct cgroup_setting **) calloc(1, num_set*sizeof(struct cgroup_setting*));
            for (int i = 0; i < num_set; i++){
                memory->settings[i] = (struct cgroup_setting *) calloc(1, sizeof(struct cgroup_setting));
            }
            strcpy(memory->settings[0]->name, "memory.limit_in_bytes");
            strcpy(memory->settings[0]->value, optarg);
            memcpy(memory->settings[1], &self_to_task, sizeof(struct cgroup_setting));
            memory->settings[2] = NULL;
            for (int j = 0; j < 5; j++){
                if (cgroups[j] == NULL){
                    cgroups[j] = memory;
                    cgroups[j+1] = NULL;
                    break;
                }
            }
            break;
        case 'r':
            num_set = 5;
            blkio = (struct cgroups_control *) calloc(1, sizeof(struct cgroups_control));
            strcpy(blkio->control, CGRP_BLKIO_CONTROL);
            blkio->settings = (struct cgroup_setting **) calloc(1, num_set*sizeof(struct cgroup_setting*));
            for (int i = 0; i < num_set; i++){
                blkio->settings[i] = (struct cgroup_setting *) calloc(1, sizeof(struct cgroup_setting));
            }
            for (int j = 0; j < num_set; j++){
                if (cgroups[0]->settings[j] == NULL){
                    break;
                }
                blkio->settings[j] = cgroups[0]->settings[j];
            }
            if (initialized == true){
                strcpy(blkio->settings[3]->name, "blkio.throttle.read_bps_device");
                strcpy(blkio->settings[3]->value, optarg);
                blkio->settings[4] = NULL;
            }
            else {
                initialized = true;
                strcpy(blkio->settings[2]->name, "blkio.throttle.read_bps_device");
                strcpy(blkio->settings[2]->value, optarg);
                blkio->settings[3] = NULL;
                blkio->settings[4] = NULL;
            }
            cgroups[0] = blkio;
            break;
        case 'w':
            num_set = 5;
            blkio = (struct cgroups_control *) calloc(1, sizeof(struct cgroups_control));
            strcpy(blkio->control, CGRP_BLKIO_CONTROL);
            blkio->settings = (struct cgroup_setting **) calloc(1, num_set*sizeof(struct cgroup_setting*));
            for (int i = 0; i < num_set; i++){
                blkio->settings[i] = (struct cgroup_setting *) calloc(1, sizeof(struct cgroup_setting));
            }
            for (int j = 0; j < num_set; j++){
                if (cgroups[0]->settings[j] == NULL){
                    break;
                }
                blkio->settings[j] = cgroups[0]->settings[j];
            }
            if (initialized == true){
                strcpy(blkio->settings[3]->name, "blkio.throttle.write_bps_device");
                strcpy(blkio->settings[3]->value, optarg);
                blkio->settings[4] = NULL;
            }
            else {
                strcpy(blkio->settings[2]->name, "blkio.throttle.write_bps_device");
                strcpy(blkio->settings[2]->value, optarg);
                blkio->settings[3] = NULL;
                blkio->settings[4] = NULL;
                initialized = true;
            }
            cgroups[0] = blkio;
            break;
        case 'H':
            config.hostname = optarg;
            break;
        default:
            cleanup_stuff(argv, sockets);
            return EXIT_FAILURE;
        }
        last_optind = optind;
    }

    if (!config.argc || !config.mount_dir){
        cleanup_stuff(argv, sockets);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "####### > Checking if the host Linux version is compatible...");
    struct utsname host = {0};
    if (uname(&host))
    {
        fprintf(stderr, "invocation to uname() failed: %m\n");
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    int major = -1;
    int minor = -1;
    if (sscanf(host.release, "%u.%u.", &major, &minor) != 2)
    {
        fprintf(stderr, "major minor version is unknown: %s\n", host.release);
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    if (major != 4 || (minor < 7))
    {
        fprintf(stderr, "Linux version must be 4.7.x or minor version less than 7: %s\n", host.release);
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    if (strcmp(ARCH_TYPE, host.machine))
    {
        fprintf(stderr, "architecture must be x86_64: %s\n", host.machine);
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "%s on %s.\n", host.release, host.machine);

    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets))
    {
        fprintf(stderr, "invocation to socketpair() failed: %m\n");
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC))
    {
        fprintf(stderr, "invocation to fcntl() failed: %m\n");
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    config.fd = sockets[1];

    if (setup_cgroup_controls(&config, cgroups))
    {
        clean_child_structures(&config, cgroups, NULL);
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }

    void* stack = malloc(STACK_SIZE);
    if (stack == NULL){
        perror("Malloc error");
    }
    void* top = stack + STACK_SIZE;
    int clone_flags = CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS;
    child_pid = clone(&child_function, top, clone_flags | SIGCHLD, &config);

    if (child_pid == -1)
    {
        fprintf(stderr, "####### > child creation failed! %m\n");
        clean_child_structures(&config, cgroups, stack);
        cleanup_sockets(sockets);
        return EXIT_FAILURE;
    }
    close(sockets[1]);
    sockets[1] = 0;

    if (setup_child_uid_map(child_pid, sockets[0]))
    {
        if (child_pid)
            kill(child_pid, SIGKILL);
    }

    int child_status = 0;
    waitpid(child_pid, &child_status, 0);
    int exit_status = WEXITSTATUS(child_status);

    clean_child_structures(&config, cgroups, stack);
    cleanup_sockets(sockets);
    return exit_status;
}

int child_function(void *arg)
{
    struct child_config *config = arg;
    if (sethostname(config->hostname, strlen(config->hostname)) || \
                setup_child_mounts(config) || \
                setup_child_userns(config) || \
                setup_child_capabilities() || \
                setup_syscall_filters()
        )
    {
        close(config->fd);
        return -1;
    }
    if (close(config->fd))
    {
        fprintf(stderr, "invocation to close() failed: %m\n");
        return -1;
    }
    if (execve(config->argv[0], config->argv, NULL))
    {
        fprintf(stderr, "invocation to execve() failed! %m.\n");
        return -1;
    }
    return 0;
}