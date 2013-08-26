#include <stdio.h>
#include "xalloc.h"
#include "buffer.h"

void reset_buffer(struct buffer *buffer)
{
	buffer->start = buffer->end = 0;
}

void init_buffer(struct buffer *buffer, size_t grow_chunk)
{
	buffer->buffer = NULL;
	buffer->size = 0;
	buffer->grow_chunk = grow_chunk < 16 ? 16 : grow_chunk;
	reset_buffer(buffer);
}

void __grow_buffer(struct buffer *buffer, size_t size)
{
	const size_t slow_growth_limit = 1 << 20;
	size_t new_size = buffer->size;

	if (size < buffer->grow_chunk)
		size = buffer->grow_chunk;
	if (new_size && size < slow_growth_limit) {
		while (new_size - buffer->end < size)
			new_size <<= 1;
	} else
		new_size += size;
	buffer->buffer = xrealloc(buffer->buffer, new_size);
	buffer->size = new_size;
}

void free_buffer(struct buffer *buffer)
{
	free(buffer->buffer);
}

char *steal_buffer(struct buffer *buffer)
{
	char *b;

	b = xrealloc(buffer->buffer, buffer_size(buffer));
	init_buffer(buffer, 0);
	return b;
}

int unget_buffer(struct buffer *buffer, int c)
{
	if (buffer->start == 0)
		return EOF;
	buffer->start--;
	*buffer_read_pos(buffer) = c;
	return c;
}
