<?php

namespace Dcat\Admin\Form\Field;

use Dcat\Admin\Form\EmbeddedForm;
use Dcat\Admin\Form\Field;
use Dcat\Admin\Form\Field\Embeds;
use Dcat\Admin\Widgets\Form as WidgetForm;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;

/**
 * i18n版的embeds组件, 主要改动如下
 * 1. 储存进数据库时使用了json序列化, 并且再序列化前增加了I18N_PREFIX标识
*/
class I18nEmbeds extends Embeds
{

    protected $view = 'admin::form.embeds';
    protected $langList = [];

    public function __construct($column, $arguments = [])
    {
        $this->column = $column;

        $this->label = $arguments[0];
        $this->langList = $arguments[1];

        $this->builder= function (EmbeddedForm $form, $langList) {
            $fallback = config('app.fallback_locale');
            if (isset($langList[$fallback])) {
                $form->text($fallback, "【{$langList[$fallback]}】")->required()->placeholder("请输入{$this->label}内容");
                unset($langList[$fallback]);
            }
            foreach ($langList as $k=>$v) {
                $obj = $form->text($k, "【{$v}】")->placeholder("请输入{$this->label}内容");
                if ($k == config('app.fallback_locale')) {
                    $obj->required();
                }
            }
        };

        if (count($arguments) == 3) {
            list($this->label, $this->langList, $this->builder) = $arguments;
        }
        $this->customFormat(function ($value) {
            if (!is_string($value)) {
                return $value;
            }
            return json_decode(substr($value, strlen(I18N_PREFIX)), true);
        });

        $this->saving(function ($data) {
            return I18N_PREFIX . json_encode($data, JSON_UNESCAPED_UNICODE);
        });

    }

    /**
     * Build a Embedded Form and fill data.
     *
     * @return EmbeddedForm
     */
    protected function buildEmbeddedForm()
    {
//        $form = new EmbeddedForm($this->column);
        $form = new EmbeddedForm($this->getElementName());

        $form->setParent($this->form);

        $form->setResolvingFieldCallbacks($this->resolvingFieldCallbacks);

        call_user_func($this->builder, $form, $this->langList);

        $form->fill($this->getEmbeddedData());

        return $form;
    }
}
