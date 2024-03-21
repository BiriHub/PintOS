#include "kernel/list.h"
#include "listpop.h"
#include "threads/malloc.h"
#include "kernel/stdio.h"
#include <stdio.h>

void populate(struct list *l, int *a, int n);
bool compare_items(const struct list_elem *a, const struct list_elem *b, void *aux);
void print_sorted(struct list *l);
void test_priority(void);

void populate_ordered(struct list *l, int *a, int n);
void print(struct list *l);

struct item
{
    int priority;
    struct list_elem elem;
};

void populate(struct list *l, int *a, int n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        struct item *new_item = malloc(sizeof(struct item));
        new_item->priority = a[i];
        list_push_back(l, &new_item->elem);
    }
}

bool compare_items(const struct list_elem *a, const struct list_elem *b, void *aux)
{
    struct item *ia = list_entry(a, struct item, elem);
    struct item *ib = list_entry(b, struct item, elem);
    return (ia->priority < ib->priority);
}

void populate_ordered(struct list *l, int *a, int n)
{
    int i;
    for (i = 0; i < n; i++)
    {
        struct item *new_item = malloc(sizeof(struct item));
        new_item->priority = a[i];
        list_insert_ordered(l, &new_item->elem, compare_items, NULL);
    }
}

void print(struct list *l)
{
    struct list_elem *le;
    printf("Ordered list at insertion\n");
    for (le = list_begin(l); le != list_end(l); le = list_next(le))
    {
        struct item *current_element = list_entry(le, struct item, elem);
        printf("%d ", current_element->priority);
    }
    printf("\n");
}

void print_sorted(struct list *l)
{
    list_sort(l, compare_items, NULL);

    struct list_elem *le;
    for (le = list_begin(l); le != list_end(l); le = list_next(le))
    {
        struct item *current_element = list_entry(le, struct item, elem);
        printf("%d ", current_element->priority);
    }
    printf("\n");
}

void test_priority()
{
    struct list l;
    list_init(&l);

    // populate(&l, ITEMARRAY, ITEMCOUNT);

    // print_sorted(&l);

    populate_ordered(&l, ITEMARRAY, ITEMCOUNT);
    print(&l);

    while (!list_empty(&l))
    {
        struct list_elem *e = list_pop_front(&l);
        struct item *curr = list_entry(e, struct item, elem);
        free(curr);
    }
}
