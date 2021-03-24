#include <unistd.h>
#include <glib.h>


typedef struct
{
    GMainLoop *loop;
}AppData;


gboolean callback1(gpointer user_data)
{
	g_message("Call callback1, block for 3 seconds");
	sleep(3);
	return TRUE;
}


gboolean callback2(gpointer user_data)
{
	g_message("Call callback2, block for 2 seconds");
	sleep(2);
	return TRUE;
}


int main(int argc, char *argv[])
{
    GError *error = NULL;
    AppData data = { NULL };
    GSource *source = NULL;
    GSource *source2 = NULL;
    int ret = EXIT_FAILURE;

    // *context: if NULL, the default context will be used
    // is_running:
    data.loop = g_main_loop_new(NULL, FALSE);

    g_message ("Call callback1 every 1 second");
    source = g_timeout_source_new(1000);
    g_source_set_callback(source, callback1, NULL, NULL);
    g_source_attach(source, NULL);

    g_message ("Call callback2 every 1 second");
    source2 = g_timeout_source_new(1000);
    g_source_set_callback(source2, callback2, NULL, NULL);
    g_source_attach(source2, NULL);

    g_message ("Running...");
    /* init update */
    g_main_loop_run(data.loop);

    g_message ("Returned, stopping...");
    g_source_destroy(source);
    g_source_unref(source);

    ret = EXIT_SUCCESS;
untergang:
    if (source)
        g_source_destroy(source);
    if (error)
        g_error_free(error);
    if (data.loop)
        g_main_loop_unref(data.loop);

    return ret;
}
