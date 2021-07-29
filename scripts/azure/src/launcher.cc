#include <iostream>

#include <spawn.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static bool SetLimit(int resource, rlim_t limit)
{
	struct rlimit limits;
	if(0 != getrlimit(resource, &limits))
	{
		const char* errstr = strerror(errno);
		std::cerr << "getrlimit failed for " << resource << ": " << errno << ", " << errstr << "\n";
		return false;
	}

	limits.rlim_cur = limit;
	if(0 != setrlimit(resource, &limits))
	{
		const char* errstr = strerror(errno);
		std::cerr << "setrlimit failed for " << resource << ": " << errno << ", " << errstr << "\n";
		return false;
	}

	return true;
}

int main()
{
	// mmap (virtual memory) size: 26GB
	if(!SetLimit(RLIMIT_AS, 26ULL * 1024 * 1024 * 1024)) return 1;
	// heap size: 256MB
	if(!SetLimit(RLIMIT_DATA, 256 * 1024 * 1024)) return 1;
	// stack size: 2MB
	if(!SetLimit(RLIMIT_STACK, 2 * 1024 * 1024)) return 1;

	const char* const path = "/usr/lib/jvm/bin/java";
	const char* args[] = {
		"/usr/lib/jvm/bin/java",
		"-Djava.security.egd=file:/dev/./urandom",
		"-Dvertx-config-path=/app/conf/config.json",
		"-jar", "/app/uid2-operator.jar",
		NULL};

	std::cerr << "Starting:";
	for(auto arg = args; *arg != NULL; ++arg)
	{
		std::cerr << " " << *arg;
	}
	std::cerr << "\n";

	pid_t pid;
	int status = posix_spawn(&pid, path, NULL, NULL, (char**)args, environ);
	if(status == 0)
	{
		if(waitpid(pid, &status, 0) != -1)
		{
			std::cerr << "process exited with status: " << status << "\n";
		}
		else
		{
			const char* errstr = strerror(errno);
			std::cerr << "waitpid failed: " << errno << ", " << errstr << "\n";
			status = 1;
		}
	}
	else
	{
		std::cerr << "posix_spawn failed: " << status << ", " << strerror(status) << "\n";
	}

	return status;
}
