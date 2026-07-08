import { Button } from "@flycockpit/ui/components/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandList,
} from "@flycockpit/ui/components/command";
import { InputGroup, InputGroupAddon } from "@flycockpit/ui/components/input-group";
import { Popover, PopoverContent, PopoverTrigger } from "@flycockpit/ui/components/popover";
import { useAsyncSearch } from "@flycockpit/ui/hooks/use-async-search";
import { cn } from "@flycockpit/ui/lib/utils";
import { Command as CommandPrimitive } from "cmdk";
import { ChevronsUpDownIcon, LoaderIcon, SearchIcon } from "lucide-react";
import * as React from "react";

interface AsyncComboboxProps<T> {
  /** Async search function. Receives the query string and an AbortSignal for cancellation. */
  onSearch: (query: string, signal: AbortSignal) => Promise<T[]>;
  /** Called when the user selects an item. */
  onSelect: (item: T) => void;
  /** The currently selected item (controlled). */
  value?: T | null;
  /** Placeholder text shown when no value is selected. */
  placeholder?: string;
  /** Placeholder text shown in the search input. */
  searchPlaceholder?: string;
  /** Text shown when no results are found. */
  emptyText?: string;
  /** Render function for each item in the list. */
  renderItem: (item: T) => React.ReactNode;
  /** Extract a unique key from an item. */
  getKey: (item: T) => string;
  /** Extract a display label from an item (used for the trigger button). */
  getLabel: (item: T) => string;
  /** Additional class name for the trigger button. */
  className?: string;
  /** Whether the combobox is disabled. */
  disabled?: boolean;
}

function AsyncCombobox<T>({
  onSearch,
  onSelect,
  value,
  placeholder = "Select...",
  searchPlaceholder = "Search...",
  emptyText = "No results found.",
  renderItem,
  getKey,
  getLabel,
  className,
  disabled = false,
}: AsyncComboboxProps<T>) {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const { results, isLoading } = useAsyncSearch(onSearch, query);

  // Dev-only contract guard. The "IDs travel, names display" rule means the
  // trigger should show a human-readable label, never the raw id. When a
  // consumer hydrates `value` with an id placeholder (e.g. `{ id, name: id }`),
  // `getKey(value) === getLabel(value)` and the trigger renders the id. Warn so
  // the bug surfaces in dev without crashing valid slug-keyed entities. Gated
  // on NODE_ENV so the check tree-shakes out of production bundles.
  if (process.env.NODE_ENV !== "production" && value != null && getKey(value) === getLabel(value)) {
    console.warn(
      "[AsyncCombobox] getKey(value) === getLabel(value): the trigger will render the raw id, " +
        "not a human-readable name. Seed `value` with the full entity (with a distinct label) " +
        "instead of an `{ id, name: id }` placeholder. See the async-search contract " +
        "(Edit flow — seeding the initial value).",
    );
  }

  const handleSelect = React.useCallback(
    (item: T) => {
      onSelect(item);
      setOpen(false);
      setQuery("");
    },
    [onSelect],
  );

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        render={
          <Button
            variant="outline"
            role="combobox"
            aria-expanded={open}
            disabled={disabled}
            className={cn(
              "w-full justify-between font-normal",
              !value && "text-muted-foreground",
              className,
            )}
          />
        }
      >
        <span className="truncate">{value ? getLabel(value) : placeholder}</span>
        <ChevronsUpDownIcon className="ml-auto size-4 shrink-0 opacity-50" />
      </PopoverTrigger>
      <PopoverContent className="w-[var(--anchor-width)] p-0" align="start">
        <Command shouldFilter={false}>
          <div data-slot="command-input-wrapper" className="border-b pb-0">
            <InputGroup className="h-8 border-none border-input/30 bg-input/30 shadow-none! *:data-[slot=input-group-addon]:pl-2!">
              <CommandPrimitive.Input
                data-slot="command-input"
                className="w-full text-xs outline-hidden disabled:cursor-not-allowed disabled:opacity-50"
                placeholder={searchPlaceholder}
                value={query}
                onValueChange={setQuery}
              />
              <InputGroupAddon>
                {isLoading ? (
                  <LoaderIcon className="size-4 shrink-0 animate-spin opacity-50" />
                ) : (
                  <SearchIcon className="size-4 shrink-0 opacity-50" />
                )}
              </InputGroupAddon>
            </InputGroup>
          </div>
          <CommandList>
            {!isLoading && results.length === 0 && <CommandEmpty>{emptyText}</CommandEmpty>}
            {results.length > 0 && (
              <CommandGroup>
                {results.map((item) => {
                  const key = getKey(item);
                  const isSelected = value ? getKey(value) === key : false;
                  return (
                    <CommandItem
                      key={key}
                      value={key}
                      data-checked={isSelected}
                      onSelect={() => handleSelect(item)}
                    >
                      {renderItem(item)}
                    </CommandItem>
                  );
                })}
              </CommandGroup>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

export { AsyncCombobox, type AsyncComboboxProps };
