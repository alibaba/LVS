#undef TRACE_SYSTEM
#define TRACE_SYSTEM sunrpc

#if !defined(_TRACE_SUNRPC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SUNRPC_H

struct rpc_task;
#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(rpc_task_status,

	TP_PROTO(struct rpc_task *task),

	TP_ARGS(task),

	TP_STRUCT__entry(
		__field(int, status)
	),

	TP_fast_assign(
		__entry->status = task->tk_status;
	),

	TP_printk("status %d", __entry->status)
);

DEFINE_EVENT(rpc_task_status, rpc_call_status,
	TP_PROTO(struct rpc_task *task), 

	TP_ARGS(task)
);

DEFINE_EVENT(rpc_task_status, rpc_bind_status,
	TP_PROTO(struct rpc_task *task), 

	TP_ARGS(task)
);

TRACE_EVENT(rpc_connect_status,
	TP_PROTO(int status),

	TP_ARGS(status),

	TP_STRUCT__entry(
		__field(int, status)
	),

	TP_fast_assign(
		__entry->status = status;
	),

	TP_printk("status=%d", __entry->status)
);

#endif /* __TRACE_SUNRPC_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

