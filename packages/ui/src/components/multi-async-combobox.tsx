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
import { CheckIcon, ChevronsUpDownIcon, LoaderIcon, SearchIcon, XIcon } from "lucide-react";
import * as React from "react";

interface MultiAsyncComboboxProps<T> {
  /** Async search function. Receives the query string and an AbortSignal for cancellation. */
  onSearch: (query: string, signal: AbortSignal) => Promise<T[]>;
  /**
   * The currently selected items (controlled). This is `T[]` — full objects, not
   * `string[]` of ids — so chip labels can always be derived via `getLabel`.
   * Keep the matching `string[]` of ids in form state; see the async-search contract.
   */
  value: T[];
  /** Called with the next `T[]` whenever an item is toggled or a chip is removed. */
  onChange: (items: T[]) => void;
  /** Placeholder text shown when no items are selected. */
  placeholder?: string;
  /** Placeholder text shown in the search input. */
  searchPlaceholder?: string;
  /** Text shown when no results are found. */
  emptyText?: string;
  /** Render function for each item in the list. */
  renderItem: (item: T) => React.ReactNode;
  /** Extract a unique key from an item. */
  getKey: (item: T) => string;
  /** Extract a display label from an item (used for chip text). */
  getLabel: (item: T) => string;
  /** Additional class name for the trigger button. */
  className?: string;
  /** Whether the combobox is disabled. */
  disabled?: boolean;
}

function MultiAsyncCombobox<T>({
  onSearch,
  value,
  onChange,
  placeholder = "Select...",
  searchPlaceholder = "Search...",
  emptyText = "No results found.",
  renderItem,
  getKey,
  getLabel,
  className,
  disabled = false,
}: MultiAsyncComboboxProps<T>) {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const { results, isLoading } = useAsyncSearch(onSearch, query);

  // Dev-only contract guard. The "IDs travel, names display" rule means each
  // chip should show a human-readable label, never the raw id. When a consumer
  // seeds `value` with id placeholders (e.g. `{ id, name: id }`), some item
  // satisfies `getKey(item) === getLabel(item)` and the chip renders the id.
  // Warn so the bug surfaces in dev without crashing valid slug-keyed entities.
  // Gated on NODE_ENV so the check tree-shakes out of production bundles.
  if (
    process.env.NODE_ENV !== "production" &&
    value.some((item) => getKey(item) === getLabel(item))
  ) {
    console.warn(
      "[MultiAsyncCombobox] an item in `value` has getKey(item) === getLabel(item): its chip " +
        "will render the raw id, not a human-readable name. Seed `value` with full entities " +
        "(with distinct labels) instead of `{ id, name: id }` placeholders. See " +
        "the multi-select edit flow.",
    );
  }

  const handleSelect = React.useCallback(
    (item: T) => {
      const key = getKey(item);
      const isSelected = value.some((v) => getKey(v) === key);
      if (isSelected) {
        onChange(value.filter((v) => getKey(v) !== key));
      } else {
        onChange([...value, item]);
      }
    },
    [value, onChange, getKey],
  );

  const handleRemove = React.useCallback(
    (item: T) => {
      const key = getKey(item);
      onChange(value.filter((v) => getKey(v) !== key));
    },
    [value, onChange, getKey],
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
              "h-auto min-h-9 w-full justify-between py-1.5 font-normal",
              value.length === 0 && "text-muted-foreground",
              className,
            )}
          />
        }
      >
        {value.length === 0 ? (
          <span className="truncate">{placeholder}</span>
        ) : (
          <span className="flex flex-1 flex-wrap gap-1">
            {value.map((item) => {
              const label = getLabel(item);
              return (
                <span
                  key={getKey(item)}
                  className="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 text-secondary-foreground text-xs"
                >
                  <span className="truncate">{label}</span>
                  <button
                    type="button"
                    aria-label={`Remove ${label}`}
                    disabled={disabled}
                    onClick={(event) => {
                      // Stop the click from toggling the popover open.
                      event.stopPropagation();
                      handleRemove(item);
                    }}
                    className="inline-flex size-5 shrink-0 items-center justify-center rounded-sm opacity-70 transition-opacity hover:opacity-100 focus-visible:opacity-100"
                  >
                    <XIcon className="size-3" />
                  </button>
                </span>
              );
            })}
          </span>
        )}
        <ChevronsUpDownIcon className="ml-auto size-4 shrink-0 self-center opacity-50" />
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
                  const isSelected = value.some((v) => getKey(v) === key);
                  return (
                    <CommandItem
                      key={key}
                      value={key}
                      data-checked={isSelected}
                      onSelect={() => handleSelect(item)}
                    >
                      <span className="flex-1">{renderItem(item)}</span>
                      {isSelected && <CheckIcon className="ml-auto size-4 shrink-0" />}
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

export { MultiAsyncCombobox, type MultiAsyncComboboxProps };
