package form

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/action"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"

	"github.com/lucasjones/reggen"
)

const (
	// RandomStringLength is the default length for random text values.
	RandomStringLength = 8
	// ProbabilityCheck is the probability threshold for boolean random values.
	ProbabilityCheck = 0.5
	// MaxRandomInt is the upper bound for random integer values.
	MaxRandomInt = 12345
	// randomChars contains the character set for random strings - letters only (a-zA-Z), no numbers.
	randomChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// formKeyJS is appended to every detection script: formKeyOf names the form
// that owns a control (DetectedInput.FormKey). Built from the form's index among
// document.forms plus its id and action attributes — read with getAttribute
// because a control named "id" or "action" shadows the form's properties.
const formKeyJS = `
		function formKeyOf(f) {
			if (!(f instanceof HTMLFormElement)) return '';
			const idx = Array.prototype.indexOf.call(document.forms, f);
			return 'form[' + idx + ']#' + (f.getAttribute('id') || '') + '|' + (f.getAttribute('action') || '');
		}
	`

// Handler handles form detection and filling.
// DetectedInput for Go extension (detection metadata).
type Handler struct {
	config       *config.Config
	inputConfigs map[string]*action.FormInput
	rng          *rand.Rand

	// fillCtx makes value selection response-aware: reuse of identity values
	// across the crawl and target-derived / on-page-example values. Nil by
	// default (unit tests, direct construction) — when nil the Handler behaves
	// exactly as before. The crawler attaches one per crawl.
	fillCtx *FillContext
}

// SetFillContext attaches a per-crawl FillContext, enabling response-aware and
// target-derived value selection. Safe to call once during setup.
func (h *Handler) SetFillContext(fc *FillContext) {
	h.fillCtx = fc
}

// FillContext returns the attached FillContext (nil when none).
func (h *Handler) FillContext() *FillContext {
	return h.fillCtx
}

// identificationKey creates a map key from identification how and value.
func identificationKey(how, value string) string {
	return how + ":" + value
}

// parseHow converts a string to action.How.
func parseHow(how string) action.How {
	switch how {
	case "id":
		return action.HowID
	case "name":
		return action.HowName
	case "xpath":
		return action.HowXPath
	default:
		return action.HowID
	}
}

// NewHandler creates a new form handler.
func NewHandler(cfg *config.Config) *Handler {
	h := &Handler{
		config:       cfg,
		inputConfigs: make(map[string]*action.FormInput),
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	for _, inputCfg := range cfg.FormInputs {
		identification := action.NewIdentification(parseHow(inputCfg.How), inputCfg.Value)
		input := action.NewFormInput(action.GetTypeFromStr(inputCfg.Type), identification)
		// Convert values to InputValue
		for _, v := range inputCfg.Values {
			input.InputValues = append(input.InputValues, action.InputValue{Value: v, Checked: v == "1"})
		}
		key := identificationKey(inputCfg.How, inputCfg.Value)
		h.inputConfigs[key] = input
		zap.L().Debug("Loaded form input config",
			zap.String("key", key),
			zap.String("how", inputCfg.How),
			zap.String("value", inputCfg.Value),
			zap.Int("valuesCount", len(inputCfg.Values)))
	}

	return h
}

// DetectForms finds all forms on the page.
// Returns Form with DetectedInput (Go extension for detection metadata).
func (h *Handler) DetectForms(page *browser.Page) ([]*Form, error) {
	script := `(() => {
		const forms = [];
		for (const form of document.querySelectorAll('form')) {
			const formData = {
				xpath: getSkeletonXPath(form),
				action: form.action,
				method: form.method,
				inputs: []
			};

			// Find all inputs in this form
			const inputs = form.querySelectorAll('input, textarea, select');
			for (const input of inputs) {
				const inputData = {
					type: input.type || input.tagName.toLowerCase(),
					xpath: getSkeletonXPath(input),
					name: input.name || '',
					id: input.id || '',
					required: input.required,
					disabled: input.disabled,
					readOnly: input.readOnly,
					multiple: input.multiple,
					pattern: input.pattern || '',
					minlength: input.minLength || 0,
					maxlength: input.maxLength || 0,
					min: input.min || '',
					max: input.max || '',
					step: input.step || '',
					placeholder: input.placeholder || '',
					label: getLabel(input),
					accept: input.accept || '',
					defaultValue: input.value || input.getAttribute('value') || '',
					datalist: (() => { try { const dl = input.list; if (dl && dl.options) return Array.from(dl.options).map(o => o.value).filter(Boolean); } catch (e) {} return []; })(),
					formKey: formKeyOf(input.form)
				};
				formData.inputs.push(inputData);
			}
			forms.push(formData);
		}
		return forms;

		function getLabel(input) {
			if (input.id) {
				const label = document.querySelector('label[for="' + CSS.escape(input.id) + '"]');
				if (label) return label.textContent.trim();
			}
			const parent = input.closest('label');
			if (parent) {
				const clone = parent.cloneNode(true);
				clone.querySelectorAll('input,select,textarea').forEach(i => i.remove());
				return clone.textContent.trim();
			}
			const ariaLabel = input.getAttribute('aria-label');
			if (ariaLabel) return ariaLabel;
			return '';
		}

		// Generates position-based XPath like /HTML[1]/BODY[1]/DIV[3]/INPUT[2]
		function getSkeletonXPath(el) {
			const parts = [];
			let current = el;
			while (current && current.nodeType === Node.ELEMENT_NODE) {
				const tagName = current.tagName.toUpperCase();
				// Count same-tag siblings before this element
				let index = 1;
				let sibling = current.previousElementSibling;
				while (sibling) {
					if (sibling.tagName === current.tagName) index++;
					sibling = sibling.previousElementSibling;
				}
				parts.unshift(tagName + '[' + index + ']');
				current = current.parentElement;
			}
			return '/' + parts.join('/');
		}
	` + formKeyJS + `})()`

	result, err := page.Eval(script)
	if err != nil {
		return nil, fmt.Errorf("failed to detect forms: %w", err)
	}

	forms := make([]*Form, 0)

	if arr, ok := result.([]interface{}); ok {
		for _, formData := range arr {
			if formMap, ok := formData.(map[string]interface{}); ok {
				form := h.parseFormData(formMap)
				forms = append(forms, form)
			}
		}
	}

	return forms, nil
}

// parseFormData parses form data from JavaScript detection.
func (h *Handler) parseFormData(data map[string]interface{}) *Form {
	// Use XPath for form identification
	xpath := getString(data, "xpath")
	form := NewForm(xpath)
	form.Action = getString(data, "action")
	form.Method = getString(data, "method")

	if inputs, ok := data["inputs"].([]interface{}); ok {
		for _, inputData := range inputs {
			if inputMap, ok := inputData.(map[string]interface{}); ok {
				input := h.parseInputData(inputMap)
				form.AddInput(input)
			}
		}
	}

	return form
}

// parseInputData parses input data from JavaScript detection.
// Returns DetectedInput which wraps action.FormInput with detection metadata.
func (h *Handler) parseInputData(data map[string]interface{}) *DetectedInput {
	typeStr := getString(data, "type")
	inputType := action.GetTypeFromStr(typeStr)
	xpath := getString(data, "xpath") // Skeleton XPath from JS
	name := getString(data, "name")
	id := getString(data, "id")

	var identification *action.Identification
	var configuredInput *action.FormInput

	if id != "" {
		identification = action.NewIdentification(action.HowID, id)
		key := identificationKey("id", id)
		configuredInput = h.inputConfigs[key]
	} else if name != "" {
		identification = action.NewIdentification(action.HowName, name)
		key := identificationKey("name", name)
		configuredInput = h.inputConfigs[key]
	} else if xpath != "" {
		identification = action.NewIdentification(action.HowXPath, xpath)
		key := identificationKey("xpath", xpath)
		configuredInput = h.inputConfigs[key]
	}

	// Create FormInput
	formInput := action.NewFormInput(inputType, identification)

	// Copy configured values if found
	if configuredInput != nil {
		formInput.InputValues = configuredInput.InputValues
		zap.L().Debug("Found configured values for input",
			zap.String("how", string(identification.How)),
			zap.String("value", identification.Value),
			zap.Int("valuesCount", len(configuredInput.InputValues)))
	}

	// Create DetectedInput with metadata (Go extension)
	detected := NewDetectedInput(formInput)
	detected.Name = name
	detected.ID = id
	detected.XPath = xpath
	detected.Required = getBool(data, "required")
	detected.Disabled = getBool(data, "disabled")
	detected.ReadOnly = getBool(data, "readOnly")
	detected.Multiple = getBool(data, "multiple")
	detected.Pattern = getString(data, "pattern")
	detected.MinLength = getInt(data, "minlength")
	detected.MaxLength = getInt(data, "maxlength")
	detected.Min = getString(data, "min")
	detected.Max = getString(data, "max")
	detected.Step = getString(data, "step")
	detected.Placeholder = getString(data, "placeholder")
	detected.Label = getString(data, "label")
	detected.Accept = getString(data, "accept")
	detected.DefaultValue = getString(data, "defaultValue")
	detected.DatalistOptions = getStringSlice(data, "datalist")
	detected.Hidden = getBool(data, "hidden")
	detected.TriggerXPath = getString(data, "triggerXPath")
	detected.FormKey = getString(data, "formKey")

	return detected
}

// DetectInputs finds all form inputs on the page (not limited to forms).
// Returns DetectedInput slice (Go extension for detection metadata).
func (h *Handler) DetectInputs(page *browser.Page) ([]*DetectedInput, error) {
	inputs, _, err := h.DetectInputsForAction(page, "")
	return inputs, err
}

// DetectInputsForAction is DetectInputs plus, in the same page evaluation, the
// FormKey of the form that owns the element at actionXPath — the form a click
// on it would submit (honoring the form= attribute; "" when the element is
// outside any form, cannot be resolved, or actionXPath is empty).
func (h *Handler) DetectInputsForAction(page *browser.Page, actionXPath string) ([]*DetectedInput, string, error) {
	xpathLiteral, err := json.Marshal(actionXPath)
	if err != nil {
		return nil, "", fmt.Errorf("encode action xpath: %w", err)
	}
	script := `(() => {
		const actionXPath = ` + string(xpathLiteral) + `;
		const inputs = [];
		for (const input of document.querySelectorAll('input, textarea, select')) {
			const hidden = isHidden(input);
			const inputData = {
				type: input.type || input.tagName.toLowerCase(),
				xpath: getSkeletonXPath(input),
				name: input.name || '',
				id: input.id || '',
				required: input.required,
				disabled: input.disabled,
				readOnly: input.readOnly,
				multiple: input.multiple,
				pattern: input.pattern || '',
				minlength: input.minLength || 0,
				maxlength: input.maxLength || 0,
				min: input.min || '',
				max: input.max || '',
				step: input.step || '',
				placeholder: input.placeholder || '',
				label: getLabel(input),
				accept: input.accept || '',
				defaultValue: input.value || input.getAttribute('value') || '',
				datalist: (() => { try { const dl = input.list; if (dl && dl.options) return Array.from(dl.options).map(o => o.value).filter(Boolean); } catch (e) {} return []; })(),
				hidden: hidden,
				triggerXPath: hidden && input.type === 'file' ? findTriggerXPath(input) : '',
				formKey: formKeyOf(input.form)
			};
			inputs.push(inputData);
		}
		return { inputs: inputs, actionFormKey: actionFormKey(actionXPath) };

		function actionFormKey(xp) {
			if (!xp) return '';
			let el = null;
			try {
				el = document.evaluate(xp, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
			} catch (e) { return ''; }
			if (!el || el.nodeType !== Node.ELEMENT_NODE) return '';
			// .form is the owner for buttons/inputs/labels (form= attribute
			// included); anything else submits the form it sits in, if any.
			const owner = (el.form instanceof HTMLFormElement) ? el.form : el.closest('form');
			return formKeyOf(owner);
		}

		// Check if element is visually hidden
		function isHidden(el) {
			if (el.hidden || el.type === 'hidden') return true;
			const style = getComputedStyle(el);
			if (style.display === 'none' || style.visibility === 'hidden') return true;
			if (style.opacity === '0') return true;
			const rect = el.getBoundingClientRect();
			if (rect.width === 0 || rect.height === 0) return true;
			if (parseFloat(style.width) === 0 || parseFloat(style.height) === 0) return true;
			return false;
		}

		// Find trigger element for hidden file input
		function findTriggerXPath(fileInput) {
			// 1. Check for label with for attribute
			if (fileInput.id) {
				const label = document.querySelector('label[for="' + CSS.escape(fileInput.id) + '"]');
				if (label && !isHidden(label)) return getSkeletonXPath(label);
			}

			// 2. Check parent label
			const parentLabel = fileInput.closest('label');
			if (parentLabel && !isHidden(parentLabel)) return getSkeletonXPath(parentLabel);

			// 3. Check sibling button/link
			const parent = fileInput.parentElement;
			if (parent) {
				const trigger = parent.querySelector('button, a, [role="button"], .btn, .upload-btn');
				if (trigger && !isHidden(trigger)) return getSkeletonXPath(trigger);
			}

			// 4. Check for element that triggers via onclick
			const allElements = document.querySelectorAll('button, a, [role="button"], label, div, span');
			for (const el of allElements) {
				if (isHidden(el)) continue;
				const onclick = el.getAttribute('onclick') || '';
				if (onclick.includes(fileInput.id) || onclick.includes('.click()')) {
					return getSkeletonXPath(el);
				}
			}

			return '';
		}

		function getLabel(input) {
			if (input.id) {
				const label = document.querySelector('label[for="' + CSS.escape(input.id) + '"]');
				if (label) return label.textContent.trim();
			}
			const parent = input.closest('label');
			if (parent) {
				const clone = parent.cloneNode(true);
				clone.querySelectorAll('input,select,textarea').forEach(i => i.remove());
				return clone.textContent.trim();
			}
			const ariaLabel = input.getAttribute('aria-label');
			if (ariaLabel) return ariaLabel;
			return '';
		}

		// Generates position-based XPath like /HTML[1]/BODY[1]/DIV[3]/INPUT[2]
		function getSkeletonXPath(el) {
			const parts = [];
			let current = el;
			while (current && current.nodeType === Node.ELEMENT_NODE) {
				const tagName = current.tagName.toUpperCase();
				// Count same-tag siblings before this element
				let index = 1;
				let sibling = current.previousElementSibling;
				while (sibling) {
					if (sibling.tagName === current.tagName) index++;
					sibling = sibling.previousElementSibling;
				}
				parts.unshift(tagName + '[' + index + ']');
				current = current.parentElement;
			}
			return '/' + parts.join('/');
		}
	` + formKeyJS + `})()`

	result, err := page.Eval(script)
	if err != nil {
		return nil, "", fmt.Errorf("failed to detect inputs: %w", err)
	}

	inputs := make([]*DetectedInput, 0)
	actionForm := ""

	if resultMap, ok := result.(map[string]interface{}); ok {
		actionForm = getString(resultMap, "actionFormKey")
		if arr, ok := resultMap["inputs"].([]interface{}); ok {
			for _, inputData := range arr {
				if inputMap, ok := inputData.(map[string]interface{}); ok {
					input := h.parseInputData(inputMap)
					inputs = append(inputs, input)
				}
			}
		}
	}

	// Web-component apps render their form fields inside shadow roots, invisible
	// to the document.querySelectorAll above. Surface those too so login/register
	// forms in design-system components get filled and submitted. They carry no
	// FormKey: a shadow-root control cannot belong to a light-DOM form.
	inputs = append(inputs, h.detectShadowInputs(page)...)

	return inputs, actionForm, nil
}

// detectShadowInputs finds fillable inputs inside shadow roots (which the
// light-DOM detection misses) and returns them identified by a stable
// data-vgo-uid attribute selector that getElementByIdentification re-resolves.
func (h *Handler) detectShadowInputs(page *browser.Page) []*DetectedInput {
	elems, err := page.ShadowElements("input, textarea, select")
	if err != nil || len(elems) == 0 {
		return nil
	}

	attr := func(el *browser.Element, name string) string {
		v, _ := el.Attribute(name)
		if v == "<nil>" {
			return ""
		}
		return v
	}

	out := make([]*DetectedInput, 0, len(elems))
	for _, el := range elems {
		uid := attr(el, browser.ShadowUIDAttr)
		if uid == "" {
			continue
		}
		typeStr := attr(el, "type")
		if typeStr == "" {
			if tag, terr := el.TagName(); terr == nil {
				typeStr = strings.ToLower(tag)
			}
		}
		switch strings.ToLower(typeStr) {
		case "submit", "button", "image", "reset":
			continue // not fillable
		}

		ident := action.NewIdentification(action.HowID, browser.ShadowUIDSelector(uid))
		d := NewDetectedInput(action.NewFormInput(action.GetTypeFromStr(typeStr), ident))
		d.Name = attr(el, "name")
		d.ID = attr(el, "id")
		d.Placeholder = attr(el, "placeholder")
		d.Pattern = attr(el, "pattern")
		d.Min = attr(el, "min")
		d.Max = attr(el, "max")
		if attr(el, "disabled") != "" {
			d.Disabled = true
		}
		if attr(el, "readonly") != "" {
			d.ReadOnly = true
		}
		out = append(out, d)
	}
	return out
}

// DetectAll finds all forms AND orphan inputs (inputs not inside any <form>) in a single JS call.
// Returns forms (with their inputs) and orphan inputs separately.
// Orphan inputs include a SubmitXPath hint pointing to the nearest submit-like element.
func (h *Handler) DetectAll(page *browser.Page) ([]*Form, []*DetectedInput, error) {
	script := `(() => {
		const result = { forms: [], orphanInputs: [] };

		// 1. Collect all <form> elements with their inputs
		for (const form of document.querySelectorAll('form')) {
			const formData = {
				xpath: getSkeletonXPath(form),
				action: form.action,
				method: form.method,
				inputs: []
			};
			for (const input of form.querySelectorAll('input, textarea, select')) {
				formData.inputs.push(extractInput(input));
			}
			result.forms.push(formData);
		}

		// 2. Collect orphan inputs (not inside any <form>)
		for (const input of document.querySelectorAll('input, textarea, select')) {
			if (input.closest('form')) continue;
			const data = extractInput(input);
			data.submitXPath = findNearbySubmit(input);
			result.orphanInputs.push(data);
		}

		return result;

		function extractInput(input) {
			const hidden = isHidden(input);
			return {
				type: input.type || input.tagName.toLowerCase(),
				xpath: getSkeletonXPath(input),
				name: input.name || '',
				id: input.id || '',
				required: input.required,
				disabled: input.disabled,
				readOnly: input.readOnly,
				multiple: input.multiple,
				pattern: input.pattern || '',
				minlength: input.minLength || 0,
				maxlength: input.maxLength || 0,
				min: input.min || '',
				max: input.max || '',
				step: input.step || '',
				placeholder: input.placeholder || '',
				label: getLabel(input),
				accept: input.accept || '',
				defaultValue: input.value || input.getAttribute('value') || '',
				datalist: (() => { try { const dl = input.list; if (dl && dl.options) return Array.from(dl.options).map(o => o.value).filter(Boolean); } catch (e) {} return []; })(),
				hidden: hidden,
				triggerXPath: hidden && input.type === 'file' ? findTriggerXPath(input) : '',
				formKey: formKeyOf(input.form)
			};
		}

		function isHidden(el) {
			if (el.hidden || el.type === 'hidden') return true;
			const style = getComputedStyle(el);
			if (style.display === 'none' || style.visibility === 'hidden') return true;
			if (style.opacity === '0') return true;
			const rect = el.getBoundingClientRect();
			if (rect.width === 0 || rect.height === 0) return true;
			if (parseFloat(style.width) === 0 || parseFloat(style.height) === 0) return true;
			return false;
		}

		function findNearbySubmit(input) {
			let el = input.parentElement;
			for (let depth = 0; el && depth < 5; depth++, el = el.parentElement) {
				const btn = el.querySelector('button, input[type="submit"], input[type="button"], a[role="button"], [type="submit"]');
				if (btn && btn !== input && !isHidden(btn)) return getSkeletonXPath(btn);
			}
			return '';
		}

		function findTriggerXPath(fileInput) {
			if (fileInput.id) {
				const label = document.querySelector('label[for="' + CSS.escape(fileInput.id) + '"]');
				if (label && !isHidden(label)) return getSkeletonXPath(label);
			}
			const parentLabel = fileInput.closest('label');
			if (parentLabel && !isHidden(parentLabel)) return getSkeletonXPath(parentLabel);
			const parent = fileInput.parentElement;
			if (parent) {
				const trigger = parent.querySelector('button, a, [role="button"], .btn, .upload-btn');
				if (trigger && !isHidden(trigger)) return getSkeletonXPath(trigger);
			}
			return '';
		}

		function getLabel(input) {
			if (input.id) {
				const label = document.querySelector('label[for="' + CSS.escape(input.id) + '"]');
				if (label) return label.textContent.trim();
			}
			const parent = input.closest('label');
			if (parent) {
				const clone = parent.cloneNode(true);
				clone.querySelectorAll('input,select,textarea').forEach(i => i.remove());
				return clone.textContent.trim();
			}
			const ariaLabel = input.getAttribute('aria-label');
			if (ariaLabel) return ariaLabel;
			return '';
		}

		function getSkeletonXPath(el) {
			const parts = [];
			let current = el;
			while (current && current.nodeType === Node.ELEMENT_NODE) {
				const tagName = current.tagName.toUpperCase();
				let index = 1;
				let sibling = current.previousElementSibling;
				while (sibling) {
					if (sibling.tagName === current.tagName) index++;
					sibling = sibling.previousElementSibling;
				}
				parts.unshift(tagName + '[' + index + ']');
				current = current.parentElement;
			}
			return '/' + parts.join('/');
		}
	` + formKeyJS + `})()`

	result, err := page.Eval(script)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to detect all: %w", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		return nil, nil, nil
	}

	// Parse forms
	var forms []*Form
	if arr, ok := resultMap["forms"].([]interface{}); ok {
		for _, formData := range arr {
			if formMap, ok := formData.(map[string]interface{}); ok {
				forms = append(forms, h.parseFormData(formMap))
			}
		}
	}

	// Parse orphan inputs
	var orphans []*DetectedInput
	if arr, ok := resultMap["orphanInputs"].([]interface{}); ok {
		for _, inputData := range arr {
			if inputMap, ok := inputData.(map[string]interface{}); ok {
				input := h.parseInputData(inputMap)
				input.SubmitXPath = getString(inputMap, "submitXPath")
				orphans = append(orphans, input)
			}
		}
	}

	return forms, orphans, nil
}

// ErrUploadNotPermitted is returned for a file input when the interaction
// policy does not permit uploads: no file is selected (or generated), and the
// input is reported as unsupported by policy rather than silently skipped.
var ErrUploadNotPermitted = errors.New("file upload not permitted by the interaction policy")

// FillResult contains the result of filling a form input.
type FillResult struct {
	Input   *DetectedInput
	Outcome FillOutcome
	Error   error
}

// Success reports whether the input counts as filled: an outcome that wrote a
// value (verified or attempted) and no error. A skipped, rejected or unsupported
// input is not a success even though it carries no error.
//
// Derived rather than stored, so it cannot disagree with Outcome and Error.
func (fr *FillResult) Success() bool { return fr.Error == nil && fr.Outcome.Succeeded() }

// FillInputsResult contains the result of filling multiple inputs, one counter
// per FillOutcome plus Failed for fills that errored. Unsupported counts inputs
// the policy did not permit (file inputs without upload permission) — neither a
// success nor a failure.
type FillInputsResult struct {
	Results     []*FillResult
	Failed      int
	Verified    int
	Attempted   int
	Rejected    int
	Skipped     int
	Unsupported int
}

// Succeeded is the number of inputs that were written: verified plus attempted.
// It never includes a skipped control. Derived rather than stored, so it cannot
// drift from the counters it sums.
func (r *FillInputsResult) Succeeded() int { return r.Verified + r.Attempted }

// add records one input's result under its outcome.
func (r *FillInputsResult) add(fr *FillResult) {
	r.Results = append(r.Results, fr)
	switch {
	case fr.Outcome == FillUnsupported:
		r.Unsupported++
	case fr.Error != nil:
		r.Failed++
	case fr.Outcome == FillVerified:
		r.Verified++
	case fr.Outcome == FillAttempted:
		r.Attempted++
	case fr.Outcome == FillRejected:
		r.Rejected++
	case fr.Outcome == FillSkipped:
		r.Skipped++
	}
}

// HasErrors returns true if any input failed to fill.
func (r *FillInputsResult) HasErrors() bool {
	return r.Failed > 0
}

// HasUnverified reports whether any input was written without its value being
// confirmed: rejected by its read-back, or written with no read-back at all.
func (r *FillInputsResult) HasUnverified() bool {
	return r.Rejected > 0 || r.Attempted > 0
}

// Errors returns all errors that occurred during filling. A policy refusal
// (ErrUploadNotPermitted) is not a fill error and is left out.
func (r *FillInputsResult) Errors() []error {
	errs := make([]error, 0, r.Failed)
	for _, result := range r.Results {
		if result.Error != nil && !errors.Is(result.Error, ErrUploadNotPermitted) {
			errs = append(errs, result.Error)
		}
	}
	return errs
}

// FillInputs fills the given inputs with configured or random values.
// Returns detailed results including any errors that occurred.
func (h *Handler) FillInputs(page *browser.Page, inputs []*DetectedInput) *FillInputsResult {
	zap.L().Debug("Filling form inputs",
		zap.Int("input_count", len(inputs)),
		zap.String("mode", string(h.config.FormFillMode)))

	result := &FillInputsResult{
		Results: make([]*FillResult, 0, len(inputs)),
	}

	for _, input := range inputs {
		fillResult := &FillResult{Input: input}

		// Get identification value for logging
		idValue := ""
		if input.FormInput != nil && input.Identification != nil {
			idValue = input.Identification.Value
		}

		outcome, err := h.FillInput(page, input)
		switch {
		case errors.Is(err, ErrUploadNotPermitted):
			fillResult.Outcome, fillResult.Error = FillUnsupported, err
			zap.L().Debug("Input not filled: unsupported by policy",
				zap.String("identification", idValue), zap.String("type", string(input.Type)))
		case err != nil:
			fillResult.Error = fmt.Errorf("failed to fill input %s: %w", idValue, err)
			zap.L().Debug("Input fill failed",
				zap.String("identification", idValue),
				zap.String("type", string(input.Type)),
				zap.Error(err))
		default:
			fillResult.Outcome = outcome
		}
		result.add(fillResult)
	}

	zap.L().Debug("Form inputs filled",
		zap.Int("verified", result.Verified),
		zap.Int("attempted", result.Attempted),
		zap.Int("rejected", result.Rejected),
		zap.Int("skipped", result.Skipped),
		zap.Int("failed", result.Failed),
		zap.Int("unsupported_by_policy", result.Unsupported))

	return result
}

// getElementByIdentification finds element using XPath based on Identification.
// - HowXPath: Use xpath value directly
// - HowID/HowName: Build XPath "//TAG[@name='X' or @id='X']" where TAG is INPUT/SELECT/TEXTAREA
func (h *Handler) getElementByIdentification(page *browser.Page, input *DetectedInput) (*browser.Element, error) {
	// Shadow-DOM inputs are identified by a stable attribute selector (an XPath
	// cannot cross a shadow boundary). Resolve them via Page.Element, whose
	// shadow-piercing fallback handles the tag.
	if input.Identification != nil && browser.IsShadowUIDSelector(input.Identification.Value) {
		return page.Element(input.Identification.Value)
	}

	if input.FormInput == nil || input.Identification == nil {
		// Fallback to XPath field if set
		if input.XPath != "" {
			return page.ElementX(input.XPath)
		}
		return nil, fmt.Errorf("no identification for form input")
	}

	id := input.Identification

	switch id.How {
	case action.HowXPath:
		return page.ElementX(id.Value)

	case action.HowID, action.HowName:
		// GO FIX: Escape single quotes in XPath to handle values like "father's day"
		tagName := h.getTagNameForType(input.Type)
		escapedValue := escapeXPathString(id.Value)
		xpath := fmt.Sprintf("//%s[@name=%s or @id=%s]", tagName, escapedValue, escapedValue)
		return page.ElementX(xpath)

	default:
		return nil, fmt.Errorf("unsupported identification how: %s", id.How)
	}
}

// getTagNameForType returns HTML tag name for form input type.
func (h *Handler) getTagNameForType(inputType action.InputType) string {
	switch inputType {
	case action.InputTypeSelect:
		return "SELECT"
	case action.InputTypeTextarea:
		return "TEXTAREA"
	default:
		return "INPUT"
	}
}

// HandleFormElements fills form inputs and returns the handled inputs list.
//   - Returns List<FormInput> of handled inputs
//   - For each input, creates NEW FormInput with XPath identification from actual DOM node
//   - If error occurs, adds the failing input at end of list
//   - This allows backtracking to use actual XPath instead of id/name
func (h *Handler) HandleFormElements(page *browser.Page, formInputs []*DetectedInput) []*action.FormInput {
	handled := make([]*action.FormInput, 0, len(formInputs))
	var failing *action.FormInput

	for _, input := range formInputs {
		if input.FormInput == nil {
			continue
		}
		failing = input.FormInput // Track current input in case of failure

		idValue := ""
		if input.Identification != nil {
			idValue = input.Identification.Value
		}
		zap.L().Debug("Filling in", zap.String("identification", idValue))

		if !input.CanInteract() {
			handled = append(handled, input.FormInput)
			failing = nil
			continue
		}

		elem, err := h.getElementByIdentification(page, input)
		if err != nil {
			zap.L().Debug("Could not find element for form input",
				zap.String("identification", idValue),
				zap.Error(err))
			continue // Skip but don't break
		}

		// Fill the input
		outcome, fillErr := h.fillElement(elem, input)
		if errors.Is(fillErr, ErrUploadNotPermitted) {
			zap.L().Debug("Form element not filled: unsupported by policy",
				zap.String("identification", idValue), zap.String("type", string(input.Type)))
			continue
		} else if fillErr != nil {
			if h.config.Verbose {
				zap.L().Error("Could not handle form element",
					zap.String("identification", idValue),
					zap.Error(fillErr))
			} else {
				zap.L().Debug("Could not handle form element",
					zap.String("identification", idValue),
					zap.Error(fillErr))
			}
			continue
		}
		if outcome == FillRejected {
			// Still handled — the control was acted on and its XPath is valid for
			// backtracking — but its value did not stick.
			zap.L().Debug("Form element value did not stick",
				zap.String("identification", idValue), zap.String("type", string(input.Type)))
		}

		actualXPath := h.getElementXPath(page, elem)
		if actualXPath != "" {
			xpathId := action.NewIdentification(action.HowXPath, actualXPath)
			handledInput := action.NewFormInput(input.Type, xpathId)
			handledInput.InputValues = input.InputValues
			handled = append(handled, handledInput)
		} else {
			handled = append(handled, input.FormInput)
		}

		failing = nil
	}

	// On error: appends the failing input. On success: appends empty sentinel FormInput.
	if failing != nil {
		handled = append(handled, failing)
	} else {
		handled = append(handled, &action.FormInput{})
	}

	return handled
}

// GetFormInputs returns all form inputs detected on current DOM.
//   - Gets DOM from browser
//   - Finds all INPUT, TEXTAREA, SELECT elements
//   - For each, calls formInputValueHelper.getFormInputWithIndexValue()
//   - Returns list of FormInput with values from config
func (h *Handler) GetFormInputs(page *browser.Page) []*action.FormInput {
	inputs, err := h.DetectInputs(page)
	if err != nil {
		zap.L().Error("Failed to detect form inputs", zap.Error(err))
		return make([]*action.FormInput, 0)
	}

	// Convert DetectedInput to action.FormInput
	return ToFormInputs(inputs)
}

// getElementXPath gets the XPath of an element.
func (h *Handler) getElementXPath(_ *browser.Page, elem *browser.Element) string {
	// CRITICAL: Must use regular function (not arrow function) so that `this` is bound correctly
	// when rod wraps the script with .apply(this, arguments).
	// Arrow functions don't have their own `this` binding - they inherit from enclosing scope.
	script := `function() {
		const parts = [];
		let current = this;
		while (current && current.nodeType === Node.ELEMENT_NODE) {
			let index = 1;
			let sibling = current.previousElementSibling;
			while (sibling) {
				if (sibling.tagName === current.tagName) index++;
				sibling = sibling.previousElementSibling;
			}
			const tagName = current.tagName.toLowerCase();
			parts.unshift(tagName + '[' + index + ']');
			current = current.parentElement;
		}
		return '/' + parts.join('/');
	}`

	result, err := elem.EvalWithResult(script)
	if err != nil {
		return ""
	}

	if s, ok := result.(string); ok {
		return s
	}
	return ""
}

// fillElement fills an element with the appropriate value based on input type.
// Internal method used by HandleFormElements.
func (h *Handler) fillElement(elem *browser.Element, input *DetectedInput) (FillOutcome, error) {
	value := h.getValueForInput(input)

	if input.FormInput == nil {
		return "", fmt.Errorf("no form input")
	}

	if input.Type != action.InputTypeFile {
		return h.fillControl(elem, input, value)
	}
	if !h.uploadsPermitted() {
		return FillUnsupported, ErrUploadNotPermitted
	}
	// GO EXTENSION: File upload support with smart file type selection
	// Use configured path if provided, otherwise select based on accept attribute
	if value == "" {
		var err error
		value, err = GetFilePathForAccept(input.Accept)
		if err != nil {
			return "", fmt.Errorf("failed to get upload file for accept=%q: %w", input.Accept, err)
		}
	}
	return attempted(FillFile(elem, []string{value}))
}

// fillControl writes value into a non-file control according to the input's
// type and reports what the write achieved. File inputs stay with the callers,
// which differ in how a hidden one is reached.
func (h *Handler) fillControl(elem *browser.Element, input *DetectedInput, value string) (FillOutcome, error) {
	switch input.Type {
	case action.InputTypeHidden:
		return attempted(FillHidden(elem, value))

	case action.InputTypeCheckbox:
		checked := value == "true" || value == "1" || value == "checked"
		return FillCheckbox(elem, checked)

	case action.InputTypeRadio:
		return FillRadio(elem, value)

	case action.InputTypeSelect:
		if input.Multiple && len(input.GetValues()) > 1 {
			return FillSelectMultiple(elem, input.GetValues())
		}
		if value == "" {
			options, err := GetSelectAllOptions(elem)
			if err == nil && len(options) > 0 {
				value = options[h.rng.Intn(len(options))]
			}
		}
		if value == "" {
			return FillSkipped, nil // No options available
		}
		return FillSelect(elem, value)

	default:
		// Text-like types, and anything unrecognized tried as text. FillText
		// writes nothing for an empty value.
		if value == "" {
			return FillSkipped, nil
		}
		return attempted(FillText(elem, value))
	}
}

// attempted is the outcome of a write with no read-back.
func attempted(err error) (FillOutcome, error) {
	if err != nil {
		return "", err
	}
	return FillAttempted, nil
}

// uploadsPermitted reports whether the interaction policy lets the crawl attach
// files. Checked before a fixture is chosen or generated.
func (h *Handler) uploadsPermitted() bool {
	return h.config != nil && h.config.Policy.UploadFiles
}

// FillInput fills a single input based on its type and reports the outcome
// (meaningful only when the error is nil). A disabled/readonly input is
// FillSkipped; a file input the policy does not permit is FillUnsupported with
// ErrUploadNotPermitted.
func (h *Handler) FillInput(page *browser.Page, input *DetectedInput) (FillOutcome, error) {
	idValue := ""
	if input.FormInput != nil && input.Identification != nil {
		idValue = input.Identification.Value
	}

	if !input.CanInteract() {
		zap.L().Debug("Input not interactable, skipping",
			zap.String("identification", idValue),
			zap.Bool("disabled", input.Disabled),
			zap.Bool("readonly", input.ReadOnly))
		return FillSkipped, nil
	}

	// The policy is checked before the element lookup and value selection, so
	// a refused upload neither touches the page nor chooses a fixture.
	if input.Type == action.InputTypeFile && !h.uploadsPermitted() {
		return FillUnsupported, ErrUploadNotPermitted
	}

	elem, err := h.getElementByIdentification(page, input)
	if err != nil {
		return "", fmt.Errorf("element not found (identification: %s): %w", idValue, err)
	}

	value := h.getValueForInput(input)
	zap.L().Debug("Filling input",
		zap.String("identification", idValue),
		zap.String("type", string(input.Type)),
		zap.String("value", value),
		zap.Bool("hasConfiguredValues", input.HasValues()))

	if input.FormInput == nil {
		return "", fmt.Errorf("no form input")
	}

	if input.Type != action.InputTypeFile {
		return h.fillControl(elem, input, value)
	}

	// GO EXTENSION: File upload support with smart file type selection
	// Determine file path: configured value or smart selection based on accept
	filePath := value
	if filePath == "" {
		filePath, err = GetFilePathForAccept(input.Accept)
		if err != nil {
			return "", fmt.Errorf("failed to get upload file for accept=%q: %w", input.Accept, err)
		}
	}

	// If hidden input with trigger, use dialog interception
	if input.Hidden && input.TriggerXPath != "" {
		triggerElem, err := page.ElementX(input.TriggerXPath)
		if err != nil {
			return "", fmt.Errorf("failed to find trigger element: %w", err)
		}
		return attempted(FillFileViaDialog(page, triggerElem, []string{filePath}))
	}

	// Direct file input - use SetFiles
	return attempted(FillFile(elem, []string{filePath}))
}

// getValueForInput returns the appropriate value for an input.
// Priority: 1) Configured value, 2) Constraint-aware, 3) Smart detection, 4) Random/Default
func (h *Handler) getValueForInput(input *DetectedInput) string {
	// 1. Use configured value if available (highest priority)
	if input.HasValues() {
		return input.NextValue()
	}

	// 2. Constraint-aware generation from HTML5 validation attributes
	if val := h.generateConstrainedValue(input); val != "" {
		return val
	}

	// 2.5 Response-aware value (real crawls only — active when a FillContext is
	// attached). Reuses an identity value already used this crawl (keeping a
	// register→login flow consistent), prefers a value the page itself suggests,
	// and derives email/username from the target. No FillContext → skipped, so
	// direct/unit construction keeps the original behavior.
	if v, ok := h.responseAwareValue(input); ok {
		return v
	}

	// 3. Strict HTML5 typed inputs (url/tel/number/range/color/date/time) need a
	// format-valid value: the name-based smart step below returns "a" for an
	// unmatched field, which these types reject — so the form fails validation
	// and a multi-step flow stalls. Resolve them by type first. Text/email/
	// password/search return "" here and fall through to the smart step.
	if input.FormInput != nil {
		if val := h.typedFormatValue(input.Type); val != "" {
			return val
		}
	}

	// Skip for SELECT - smart values are text, but SELECT needs option values
	// Skip for FILE - file handling uses default file path, not smart values
	// Random option selection is handled in FillInput instead
	if input.FormInput != nil && input.Type != action.InputTypeSelect && input.Type != action.InputTypeFile {
		if smartValue := h.getSmartValue(input); smartValue != "" {
			return smartValue
		}
	}

	// 4. Generate random value if enabled
	if h.config.FormFillMode == config.FormFillRandom {
		return h.generateRandomValue(input)
	}

	// 5. Return default value based on type
	return h.getDefaultValue(input)
}

// generateRandomValue generates a random value for the input type.
func (h *Handler) generateRandomValue(input *DetectedInput) string {
	if input.FormInput == nil {
		return h.randomString(RandomStringLength)
	}

	switch input.Type {
	case action.InputTypeText, action.InputTypeTextarea:
		return h.randomString(RandomStringLength)

	case action.InputTypePassword:
		// Go extension: random password with complexity
		return h.randomString(12) + "A1!"

	case action.InputTypeEmail:
		// Go extension: random email
		return h.randomString(RandomStringLength) + "@example.com"

	case action.InputTypeNumber:
		return fmt.Sprintf("%d", h.rng.Intn(MaxRandomInt))

	case action.InputTypeCheckbox:
		if h.rng.Float64() > ProbabilityCheck {
			return "1"
		}
		return "0"

	case action.InputTypeRadio:
		if h.rng.Float64() > ProbabilityCheck {
			return "1"
		}
		return "0"

	case action.InputTypeSelect:
		return ""

	case action.InputTypeFile:
		// GO EXTENSION: File inputs don't use random values - use default file
		return ""

	default:
		return h.randomString(RandomStringLength)
	}
}

func (h *Handler) randomString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = randomChars[h.rng.Intn(len(randomChars))]
	}
	return string(result)
}

// generateConstrainedValue generates value respecting HTML5 validation constraints.
func (h *Handler) generateConstrainedValue(input *DetectedInput) string {
	// Pattern regex has highest priority
	if input.Pattern != "" {
		if val := h.generateFromPattern(input.Pattern, input.MinLength, input.MaxLength); val != "" {
			return val
		}
	}

	// Number/Range with min/max/step
	if input.FormInput != nil && (input.Type == action.InputTypeNumber || input.Type == action.InputTypeRange) &&
		(input.Min != "" || input.Max != "") {
		return h.generateNumberInRange(input.Min, input.Max, input.Step)
	}

	// Date with min/max → a real date inside the range (YYYY-MM-DD), so the
	// field validates and the form submits.
	if input.FormInput != nil && input.Type == action.InputTypeDate && (input.Min != "" || input.Max != "") {
		if val := h.generateDateInRange(input.Min, input.Max); val != "" {
			return val
		}
	}

	// Time with min/max → a real time inside the range (HH:MM).
	if input.FormInput != nil && input.Type == action.InputTypeTime && (input.Min != "" || input.Max != "") {
		if val := h.generateTimeInRange(input.Min, input.Max); val != "" {
			return val
		}
	}

	// String length constraints (only for text-like inputs without pattern)
	if input.FormInput != nil && input.IsTextLike() && (input.MinLength > 0 || input.MaxLength > 0) {
		return h.generateStringWithLength(input.MinLength, input.MaxLength)
	}

	return ""
}

// generateFromPattern generates string matching regex pattern using reggen.
func (h *Handler) generateFromPattern(pattern string, minLen, maxLen int) string {
	gen, err := reggen.NewGenerator(pattern)
	if err != nil {
		return ""
	}

	for i := 0; i < 10; i++ {
		val := gen.Generate(h.rng.Intn(20) + 1)
		if (minLen <= 0 || len(val) >= minLen) && (maxLen <= 0 || len(val) <= maxLen) {
			return val
		}
	}
	return gen.Generate(h.rng.Intn(20))
}

// generateNumberInRange generates number within [min, max] respecting step.
func (h *Handler) generateNumberInRange(min, max, step string) string {
	minVal := parseFloatOrDefault(min, 0)
	maxVal := parseFloatOrDefault(max, float64(MaxRandomInt))
	stepVal := parseFloatOrDefault(step, 1)

	if maxVal <= minVal {
		return formatNumber(minVal, stepVal)
	}

	steps := int((maxVal - minVal) / stepVal)
	if steps <= 0 {
		steps = 1
	}
	randomSteps := h.rng.Intn(steps + 1)
	value := minVal + float64(randomSteps)*stepVal

	return formatNumber(value, stepVal)
}

// generateStringWithLength generates string with length in [minLen, maxLen].
func (h *Handler) generateStringWithLength(minLen, maxLen int) string {
	if minLen <= 0 {
		minLen = 1
	}
	if maxLen <= 0 || maxLen < minLen {
		maxLen = minLen + RandomStringLength
	}

	length := minLen
	if maxLen > minLen {
		length = minLen + h.rng.Intn(maxLen-minLen+1)
	}
	return h.randomString(length)
}

// Helper functions for constraint-aware generation

// escapeXPathString escapes quotes in XPath string values.
// - No quotes: 'value'
// - Single quotes only: "value" (simpler than concat)
// - Double quotes only: 'value'
// - Both: concat('before', "'", 'after')
func escapeXPathString(s string) string {
	hasSingle := strings.Contains(s, "'")
	hasDouble := strings.Contains(s, "\"")

	switch {
	case !hasSingle:
		return "'" + s + "'"
	case !hasDouble:
		return "\"" + s + "\""
	default:
		// Both quotes - use concat()
		parts := strings.Split(s, "'")
		var b strings.Builder
		b.WriteString("concat(")
		for i, part := range parts {
			if i > 0 {
				b.WriteString(", \"'\", ")
			}
			b.WriteString("'")
			b.WriteString(part)
			b.WriteString("'")
		}
		b.WriteString(")")
		return b.String()
	}
}

func parseFloatOrDefault(s string, def float64) float64 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return v
}

func formatNumber(v, step float64) string {
	if step == float64(int(step)) && step >= 1 {
		return fmt.Sprintf("%.0f", v)
	}
	return fmt.Sprintf("%g", v)
}

// containsAny checks if any of the patterns are contained in target strings.
func containsAny(targets []string, patterns ...string) bool {
	for _, target := range targets {
		for _, pattern := range patterns {
			if strings.Contains(target, pattern) {
				return true
			}
		}
	}
	return false
}

// Fixed credentials for consistent register/login flow during crawling.
// FixedEmail is the address at the default identity domain; with an operator
// override the domain follows spidering.identity_email_domain (fixedEmail).
const (
	FixedUsername = "johnted132123"
	FixedEmail    = FixedUsername + "@" + config.DefaultIdentityEmailDomain
	FixedPassword = "Server2018!!"
)

// identityEmailDomain is the domain generated email addresses use.
func (h *Handler) identityEmailDomain() string {
	if h.config != nil && h.config.IdentityEmailDomain != "" {
		return h.config.IdentityEmailDomain
	}
	return config.DefaultIdentityEmailDomain
}

// fixedEmail is FixedEmail at the configured identity domain.
func (h *Handler) fixedEmail() string {
	return FixedUsername + "@" + h.identityEmailDomain()
}

// responseAwareValue resolves a value using the per-crawl FillContext: it reuses
// an identity value already used this crawl, prefers a concrete value the page
// itself suggests, and derives email/username from the target. It returns
// (value, true) when it produced a value and (‑, false) when the caller should
// fall through to the existing typed/smart/random logic. When no FillContext is
// attached it always returns (‑, false), preserving the original behavior.
func (h *Handler) responseAwareValue(input *DetectedInput) (string, bool) {
	fc := h.fillCtx
	if fc == nil || input.FormInput == nil {
		return "", false
	}

	sem := classifyField(input)
	if sem == SemUnknown {
		// Generic field: use a concrete value the page offers (value=/datalist/
		// example placeholder); otherwise defer to the existing logic.
		if v := exampleValue(input); v != "" {
			return v, true
		}
		return "", false
	}

	// Identity field: reuse the value chosen earlier this crawl so a signup and a
	// later login carry the same identity, else derive and remember one.
	if v, ok := fc.Recall(sem); ok {
		return v, true
	}
	if v := h.deriveIdentityValue(sem, input); v != "" {
		fc.Remember(sem, v)
		return v, true
	}
	return "", false
}

// deriveIdentityValue picks the value for an identity field the first time it is
// seen: a page-provided example when it fits the semantic, then a generated
// address at the identity email domain (email) or a target-derived username,
// falling back to the original smart value (the fixed credentials / static
// table) so password strength and behavior are preserved.
func (h *Handler) deriveIdentityValue(sem FieldSemantic, input *DetectedInput) string {
	switch sem {
	case SemPassword:
		// Never take a password from the page; keep the strong fixed value.
		return h.getSmartValue(input)
	case SemEmail:
		if ex := exampleValue(input); ex != "" && strings.Contains(ex, "@") {
			return ex
		}
		// Never the target's own domain: that is plausible real mail at the
		// customer's domain. See config.DefaultIdentityEmailDomain.
		return crawlLocalPart + "@" + h.identityEmailDomain()
	case SemUsername:
		if ex := exampleValue(input); ex != "" && !strings.ContainsAny(ex, " @") {
			return ex
		}
		if u := h.fillCtx.UsernameFromDomain(); u != "" {
			return u
		}
		return h.getSmartValue(input)
	default: // name, phone
		if ex := exampleValue(input); ex != "" {
			return ex
		}
		return h.getSmartValue(input)
	}
}

// getSmartValue generates intelligent values based on input name/id/placeholder/label.
// Note: email, username, password use FIXED values for consistent register/login during crawl.
func (h *Handler) getSmartValue(input *DetectedInput) string {
	name := strings.ToLower(input.Name)
	id := strings.ToLower(input.ID)
	placeholder := strings.ToLower(input.Placeholder)
	label := strings.ToLower(input.Label)
	targets := []string{name, id, placeholder, label}

	// Identity patterns - FIXED for consistent login (keyword lists shared with
	// classifyField so the two never drift).
	if containsAny(targets, emailFieldKeywords...) {
		return h.fixedEmail()
	}
	if containsAny(targets, passwordFieldKeywords...) {
		return FixedPassword
	}
	if containsAny(targets, usernameFieldKeywords...) {
		return FixedUsername
	}

	// Phone patterns
	if containsAny(targets, phoneFieldKeywords...) {
		return "+15551234567"
	}

	// Name patterns - check specific patterns first
	if containsAny(targets, firstNameFieldKeywords...) {
		return "Crawl"
	}
	if containsAny(targets, lastNameFieldKeywords...) {
		return "Tester"
	}
	if containsAny(targets, fullNameFieldKeywords...) {
		return "Crawl Tester"
	}
	// Generic "name" - avoid matching "username"
	if (name == "name" || id == "name") && !containsAny(targets, "user") {
		return "Crawl Tester"
	}

	// Address patterns - FIXED for consistent crawl
	if containsAny(targets, "address", "street", "addr", "direccion") {
		return "123 Test Street"
	}
	if containsAny(targets, "city", "ciudad") {
		return "New York"
	}
	if containsAny(targets, "zip", "postal", "postcode", "zipcode") {
		return "10001"
	}
	if containsAny(targets, "country", "pais") {
		return "United States"
	}
	if containsAny(targets, "state", "province", "region", "estado") {
		return "New York"
	}

	// Date patterns - FIXED for consistent crawl
	if containsAny(targets, "date", "dob", "birthday", "birth", "fecha") {
		return "1990-01-15"
	}

	// Age patterns
	if containsAny(targets, "age", "edad") {
		return "30"
	}

	// URL patterns
	if containsAny(targets, "url", "website", "site", "link", "homepage", "web") {
		return "https://example.com/test"
	}

	// Company patterns
	if containsAny(targets, "company", "org", "organization", "empresa", "business") {
		return "Test Company Inc"
	}

	// Credit card patterns (fake data for testing)
	if containsAny(targets, "card", "credit", "ccn", "cardnumber", "card_number") {
		return "4111111111111111" // Test Visa
	}
	if containsAny(targets, "cvv", "cvc", "security_code", "securitycode") {
		return "123"
	}
	if containsAny(targets, "expiry", "exp", "expiration") {
		return "12/25"
	}

	// Message/comment patterns
	if containsAny(targets, "message", "comment", "note", "description", "bio", "about", "text", "content", "body") {
		return "Test message for form submission"
	}

	// Search patterns
	if containsAny(targets, "search", "query", "keyword") || name == "q" || id == "q" {
		return "a"
	}

	// Title patterns
	if containsAny(targets, "title", "subject", "titulo", "asunto") {
		return "Test Title"
	}

	// Fallback - no match found
	return "a"
}

// Default format-valid values for strict HTML5 input types whose client-side
// validation rejects a generic placeholder. A date/time/url/tel field left with
// "a" (or empty) fails validation, so the form never submits and a multi-step
// flow stalls — emitting one valid value per type lets the request go through.
const (
	defaultDateValue  = "2024-06-15"
	defaultTimeValue  = "12:00"
	defaultURLValue   = "https://example.com"
	defaultTelValue   = "+15555555555"
	defaultColorValue = "#000000"
	defaultRangeValue = "50"
)

// typedFormatValue returns a format-valid value for HTML5 input types whose
// strict validation rejects a name guess / "a". Returns "" for types better
// served by name-based smart values (text/search/textarea) or fixed-credential
// values (email/password), which are resolved elsewhere — so wiring this in
// before the smart step does not disturb those.
func (h *Handler) typedFormatValue(inputType action.InputType) string {
	switch inputType {
	case action.InputTypeURL:
		return defaultURLValue
	case action.InputTypeTel:
		return defaultTelValue
	case action.InputTypeNumber:
		return "42"
	case action.InputTypeRange:
		return defaultRangeValue
	case action.InputTypeColor:
		return defaultColorValue
	case action.InputTypeDate:
		return defaultDateValue
	case action.InputTypeTime:
		return defaultTimeValue
	default:
		return ""
	}
}

// generateDateInRange returns a random YYYY-MM-DD date within [min, max].
// Either bound may be empty; an unparseable pair falls back to the default date.
func (h *Handler) generateDateInRange(min, max string) string {
	const layout = "2006-01-02"
	minT, errMin := time.Parse(layout, min)
	maxT, errMax := time.Parse(layout, max)
	switch {
	case errMin == nil && errMax == nil:
		if maxT.Before(minT) {
			minT, maxT = maxT, minT
		}
		days := int(maxT.Sub(minT).Hours() / 24)
		if days <= 0 {
			return minT.Format(layout)
		}
		return minT.AddDate(0, 0, h.rng.Intn(days+1)).Format(layout)
	case errMin == nil:
		return minT.Format(layout)
	case errMax == nil:
		return maxT.Format(layout)
	default:
		return defaultDateValue
	}
}

// generateTimeInRange returns a random HH:MM time within [min, max].
// Either bound may be empty; an unparseable pair falls back to the default time.
func (h *Handler) generateTimeInRange(min, max string) string {
	toMinutes := func(s string) (int, bool) {
		var hh, mm int
		if _, err := fmt.Sscanf(s, "%d:%d", &hh, &mm); err != nil {
			return 0, false
		}
		if hh < 0 || hh > 23 || mm < 0 || mm > 59 {
			return 0, false
		}
		return hh*60 + mm, true
	}
	lo, okLo := toMinutes(min)
	hi, okHi := toMinutes(max)
	switch {
	case okLo && okHi:
		if hi < lo {
			lo, hi = hi, lo
		}
		m := lo
		if hi > lo {
			m = lo + h.rng.Intn(hi-lo+1)
		}
		return fmt.Sprintf("%02d:%02d", m/60, m%60)
	case okLo:
		return fmt.Sprintf("%02d:%02d", lo/60, lo%60)
	case okHi:
		return fmt.Sprintf("%02d:%02d", hi/60, hi%60)
	default:
		return defaultTimeValue
	}
}

// getDefaultValue returns a default value for the input type.
func (h *Handler) getDefaultValue(input *DetectedInput) string {
	if input.FormInput == nil {
		return "a"
	}

	// Strict typed inputs (url/tel/number/range/color/date/time) take a
	// format-valid value; the switch below covers the text-oriented types.
	if v := h.typedFormatValue(input.Type); v != "" {
		return v
	}

	switch input.Type {
	case action.InputTypeText, action.InputTypeTextarea:
		return "a"

	case action.InputTypePassword:
		return "Password123!"

	case action.InputTypeEmail:
		return "test@example.com"

	case action.InputTypeNumber:
		return "42"

	case action.InputTypeCheckbox:
		return "true"

	case action.InputTypeSelect:
		// Return empty to trigger random option selection in FillInput
		return ""

	case action.InputTypeFile:
		// GO EXTENSION: Return empty - file handling uses generated default
		return ""

	default:
		return "a"
	}
}

// ResetInputs clears all inputs.
func (h *Handler) ResetInputs(page *browser.Page, inputs []*DetectedInput) error {
	for _, input := range inputs {
		elem, err := h.getElementByIdentification(page, input)
		if err != nil {
			continue
		}

		if err := ClearInput(elem); err != nil {
			continue
		}
	}

	return nil
}

// FillForm fills all inputs in a form.
func (h *Handler) FillForm(page *browser.Page, form *Form) *FillInputsResult {
	return h.FillInputs(page, form.Inputs)
}

// SubmitForm fills and submits a form.
// Returns the fill result and any submission error.
func (h *Handler) SubmitForm(page *browser.Page, form *Form) (*FillInputsResult, error) {
	// Fill the form first
	fillResult := h.FillForm(page, form)

	// Find submit button using XPath
	submitXPath := form.XPath + "//input[@type='submit'] | " +
		form.XPath + "//button[@type='submit'] | " +
		form.XPath + "//button[not(@type)]"

	elem, err := page.ElementX(submitXPath)
	if err == nil && elem != nil {
		return fillResult, elem.Click()
	}

	// Fallback: submit via JavaScript using XPath
	script := fmt.Sprintf(`
		(() => {
			const result = document.evaluate(%q, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
			if (result.singleNodeValue) {
				result.singleNodeValue.submit();
				return true;
			}
			return false;
		})()
	`, form.XPath)
	_, err = page.Eval(script)
	return fillResult, err
}

// Helper functions

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// getStringSlice extracts a []string from a JS-returned []interface{} of
// strings (e.g. datalist option values); non-string entries are skipped.
func getStringSlice(m map[string]interface{}, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return 0
}

// getIdentificationKey returns a unique key for the input based on Identification.
func getIdentificationKey(input *DetectedInput) string {
	if input.FormInput != nil && input.Identification != nil {
		return input.Identification.String()
	}
	if input.XPath != "" {
		return "xpath:" + input.XPath
	}
	return ""
}

// FillInputsPairwise tries filling inputs in pairs when full fill fails.
// IMPORTANT: Caller should already have attempted FillInputs and it failed.
// This function assumes inputs need pairwise testing, not a full retry.
// Returns (success, workedInputs) - the inputs that were successfully filled.
func (h *Handler) FillInputsPairwise(page *browser.Page, inputs []*DetectedInput) (bool, []*DetectedInput) {
	// Reset all inputs before pairwise testing
	// (caller already tried FillInputs which failed)
	_ = h.ResetInputs(page, inputs)

	// Track which inputs work (can be filled without error)
	workingInputs := make(map[string]bool)
	testedPairs := make(map[string]bool)

	// Try pairs of inputs to find which ones work together
	for i := range len(inputs) {
		for j := i + 1; j < len(inputs); j++ {
			input1 := inputs[i]
			input2 := inputs[j]

			// Create unique pair key using Identification
			key1 := getIdentificationKey(input1)
			key2 := getIdentificationKey(input2)
			pairKey := fmt.Sprintf("%s:%s", key1, key2)
			if testedPairs[pairKey] {
				continue
			}
			testedPairs[pairKey] = true

			// Reset before trying this pair
			_ = h.ResetInputs(page, []*DetectedInput{input1, input2})

			// Try filling this pair
			pair := []*DetectedInput{input1, input2}
			pairResult := h.FillInputs(page, pair)

			if pairResult.Failed == 0 {
				// Mark both inputs as working
				workingInputs[key1] = true
				workingInputs[key2] = true
			}
		}
	}

	// Collect working inputs
	worked := make([]*DetectedInput, 0)
	for _, input := range inputs {
		key := getIdentificationKey(input)
		if workingInputs[key] {
			worked = append(worked, input)
		}
	}

	// If we found working inputs, reset all and fill them once
	if len(worked) > 0 {
		_ = h.ResetInputs(page, inputs)
		finalResult := h.FillInputs(page, worked)
		return finalResult.Failed == 0, worked
	}

	return false, nil
}

// FillFormPairwise fills a form using pairwise strategy if normal fill fails.
func (h *Handler) FillFormPairwise(page *browser.Page, form *Form) (bool, []*DetectedInput) {
	return h.FillInputsPairwise(page, form.Inputs)
}
