/** Internal aliases only: this is SQL composition, never user input. */
export function evidenceWithinAssessmentScopeSql(alias = "e"): string {
  if (!/^[a-z][a-z0-9_]*$/u.test(alias)) throw new Error("Invalid internal evidence alias.");
  return `EXISTS (SELECT 1 FROM assessments scope_assessment
    WHERE scope_assessment.id = ${alias}.assessment_id
      AND scope_assessment.scope_mode = 'explicit' AND scope_assessment.catalog_id IS NOT NULL
      AND scope_assessment.framework = ${alias}.framework
      AND EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(scope_assessment.systems_json) THEN scope_assessment.systems_json ELSE '[]' END) scope_system WHERE scope_system.value = ${alias}.system)
      AND EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(scope_assessment.controls_json) THEN scope_assessment.controls_json ELSE '[]' END) scope_control WHERE scope_control.value = ${alias}.control_id))`;
}
